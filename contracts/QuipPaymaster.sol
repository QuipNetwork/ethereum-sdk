// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
// prettier-ignore
import {
    IPaymaster,
    IEntryPointStake,
    PackedUserOperation
} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {IQuipPaymaster} from "./interfaces/IQuipPaymaster.sol";
import {QuipPaymasterStorage as Storage} from "./storage/QuipPaymasterStorage.sol";

/// @title QuipPaymaster
/// @dev A UUPS-upgradeable ERC-4337 verifying paymaster. Validates per-wallet WOTS+
///      signatures from a trusted backend to authorize gas sponsorship for QuipWallet
///      UserOperations. Each sponsored wallet has its own WOTS+ key chain, so key
///      rotation serializes per-wallet rather than globally.
contract QuipPaymaster is
    IQuipPaymaster,
    Ownable,
    UUPSUpgradeable,
    Initializable
{
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CONSTANTS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev ERC-4337 v0.7 EntryPoint singleton address.
    address public constant ENTRY_POINT =
        0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    /// @dev Offset into `paymasterAndData` where custom paymaster data begins.
    ///      [0:20) paymaster address, [20:36) verificationGasLimit, [36:52) postOpGasLimit.
    uint256 private constant _PAYMASTER_DATA_OFFSET = 52;

    /// @dev Offset into `paymasterAndData` where the WOTS+ signature begins.
    ///      Everything before this offset is bound into the userOp binding hash;
    ///      the signature itself is necessarily excluded to break the circular
    ///      dependency between the signature and what it commits to.
    ///      Layout: 52 (header) + 6 (validUntil) + 6 (validAfter) + 64 (next verifier) = 128.
    uint256 private constant _PAYMASTER_SIG_OFFSET = 128;

    /// @dev Total expected `userOp.paymasterAndData` length in bytes:
    ///      128-byte bindable prefix + 2144 (WOTS+ signature: 67 × 32) = 2272.
    uint256 private constant _PAYMASTER_AND_DATA_LEN = 2272;

    /// @dev Domain tag for paymaster approval digests (WOTS+ domain-tagged, not EIP-712).
    bytes32 private constant _PAYMASTER_APPROVE_TAG =
        keccak256("quip.digest.paymasterApprove");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      CONSTRUCTOR                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor() {
        _disableInitializers();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   INTERNAL OVERRIDES                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Guard owner initialization to prevent re-initialization.
    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }

    /// @dev Restrict upgrades to the contract owner.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   EXTERNAL FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipPaymaster
    function initialize(address owner_) external initializer {
        if (owner_ == address(0)) revert ZeroAddressOwner();
        _initializeOwner(owner_);
        emit PaymasterInitialized(owner_);
    }

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /* userOpHash */,
        uint256 /* maxCost */
    ) external override returns (bytes memory context, uint256 validationData) {
        if (msg.sender != ENTRY_POINT) revert InvalidEntryPoint();

        // Reject any paymasterAndData whose length doesn't match the fixed
        // protocol layout. Out-of-bounds calldata reads inside `_verifyAndRotate`
        // would otherwise revert with an opaque panic; surplus bytes would be
        // silently ignored. Returning validationData=1 keeps the failure path
        // consistent with every other rejection branch.
        if (userOp.paymasterAndData.length != _PAYMASTER_AND_DATA_LEN) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.MalformedPayload
            );
            return ("", 1);
        }

        // Decode custom paymaster data from paymasterAndData[52:].
        // [0:6)     validUntil (uint48)
        // [6:12)    validAfter (uint48)
        // [12:76)   nextVerifier (WinternitzAddress: 32 bytes publicSeed + 32 bytes publicKeyHash)
        // [76:2220) WOTS+ signature (67 × 32 = 2144 bytes)
        if (!_verifyAndRotate(userOp)) return ("", 1);

        bytes calldata paymasterData = userOp
            .paymasterAndData[_PAYMASTER_DATA_OFFSET:];

        // Pack validationData: [0:160) authorizer=0, [160:208) validUntil, [208:256) validAfter.
        uint48 validUntil = uint48(bytes6(paymasterData[:6]));
        uint48 validAfter = uint48(bytes6(paymasterData[6:12]));
        validationData =
            (uint256(validUntil) << 160) |
            (uint256(validAfter) << 208);
        // Pack the sponsored wallet into context so postOp can attribute the
        // gas cost. EntryPoint forwards this verbatim to postOp on success.
        context = abi.encode(userOp.sender);
    }

    /// @inheritdoc IPaymaster
    /// @dev Decodes the sponsored wallet from `context` and emits
    ///      `UserOpSponsored` with the EntryPoint's mode + gas accounting so
    ///      every sponsored UserOp leaves an on-chain audit record — including
    ///      the `postOpReverted` re-entry path, where an audit trail is most
    ///      valuable precisely because something abnormal occurred. The
    ///      EntryPoint forwards the same context bytes the paymaster returned
    ///      from `validatePaymasterUserOp`, so the decode is trusting our own
    ///      output.
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    ) external override {
        if (msg.sender != ENTRY_POINT) revert InvalidEntryPoint();
        address wallet = abi.decode(context, (address));
        emit UserOpSponsored(
            wallet,
            mode,
            actualGasCost,
            actualUserOpFeePerGas
        );
    }

    /// @inheritdoc IQuipPaymaster
    function setPqVerifier(
        address wallet,
        WOTSPlus.WinternitzAddress calldata verifier
    ) external onlyOwner {
        if (
            verifier.publicSeed == bytes32(0) ||
            verifier.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqVerifierKey();

        Storage.Layout storage $ = Storage.layout();

        // Snapshot the prior verifier BEFORE any storage mutation so the
        // event carries the genuine prior state. On first-time registration
        // both fields are zero — `PqVerifierSet`'s `oldVerifier` is then the
        // zero address-pair, which is the off-chain discriminator between a
        // fresh set and an admin hot-swap.
        WOTSPlus.WinternitzAddress storage existing = $.verifiers[wallet];
        WOTSPlus.WinternitzAddress memory oldVerifier = WOTSPlus
            .WinternitzAddress({
                publicSeed: existing.publicSeed,
                publicKeyHash: existing.publicKeyHash
            });

        // Re-binding the same key on the same wallet is a no-op (the key was
        // already registered for this wallet on a prior call). Allow it for
        // ergonomics — but skip the in-use check, which would otherwise fire
        // on this wallet's own existing entry in the monotonic index.
        if (
            existing.publicSeed == verifier.publicSeed &&
            existing.publicKeyHash == verifier.publicKeyHash
        ) {
            emit PqVerifierSet(wallet, oldVerifier, verifier);
            return;
        }

        // The occupancy index is MONOTONIC: once a verifier hash is set, it
        // is never cleared — not on overwrite, not on removal, not on
        // rotation. WOTS+ is a one-time-signature scheme: a verifier that
        // ever produced a signature has had its key chain revealed on-chain,
        // so re-binding it (here or for any other wallet) would let an
        // observer forge paymaster sigs against the rebind target. Even
        // never-used registered keys stay locked because the on-chain index
        // can't tell "registered but never signed" from "registered and
        // signed" — the conservative invariant is "once seen, never reused."
        bytes32 newHash = _verifierHash(
            verifier.publicSeed,
            verifier.publicKeyHash
        );
        if ($.verifierKeyUsed[newHash]) revert VerifierKeyInUse();

        $.verifiers[wallet] = verifier;
        $.verifierKeyUsed[newHash] = true;
        emit PqVerifierSet(wallet, oldVerifier, verifier);
    }

    /// @inheritdoc IQuipPaymaster
    function removePqVerifier(address wallet) external onlyOwner {
        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress storage existing = $.verifiers[wallet];

        if (
            existing.publicSeed == bytes32(0) ||
            existing.publicKeyHash == bytes32(0)
        ) revert PqVerifierNotRegistered();

        // Deliberately do NOT clear `verifierKeyUsed[hash(existing)]`. The
        // occupancy index is monotonic — see `setPqVerifier` for the full
        // rationale. Removal only drops the wallet→verifier binding so the
        // wallet can no longer sponsor; the key itself stays permanently
        // locked from re-registration.
        delete $.verifiers[wallet];
        emit PqVerifierRemoved(wallet);
    }

    /// @inheritdoc IQuipPaymaster
    function deposit() external payable {
        IEntryPointStake(ENTRY_POINT).depositTo{value: msg.value}(
            address(this)
        );
    }

    /// @inheritdoc IQuipPaymaster
    function withdrawTo(address payable to, uint256 amount) external onlyOwner {
        IEntryPointStake(ENTRY_POINT).withdrawTo(to, amount);
    }

    /// @inheritdoc IQuipPaymaster
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        IEntryPointStake(ENTRY_POINT).addStake{value: msg.value}(
            unstakeDelaySec
        );
    }

    /// @inheritdoc IQuipPaymaster
    function unlockStake() external onlyOwner {
        IEntryPointStake(ENTRY_POINT).unlockStake();
    }

    /// @inheritdoc IQuipPaymaster
    function withdrawStake(address payable to) external onlyOwner {
        IEntryPointStake(ENTRY_POINT).withdrawStake(to);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  INTERNAL FUNCTIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Verifies the WOTS+ signature and rotates the per-wallet verifier key.
    ///      Rotation is committed immediately so the key is rotated regardless of whether
    ///      the execution phase succeeds or fails. This is critical because WOTS+ is a
    ///      one-time signature scheme — the signing key is effectively compromised once
    ///      the signature is revealed on-chain.
    ///
    ///      The signed digest binds a `userOpBindingHash` that covers the same field
    ///      set as ERC-4337's `userOpHash` but with `paymasterAndData` truncated to
    ///      `[:_PAYMASTER_SIG_OFFSET]` — i.e. everything except the WOTS+ signature
    ///      region itself. That truncation is necessary because the signature lives
    ///      inside `paymasterAndData`, so binding the full hash would be circular.
    ///      Backend signers MUST replicate this hash construction off-chain.
    ///
    ///      CALLER MUST: ensure `userOp.paymasterAndData.length ==
    ///      `_PAYMASTER_AND_DATA_LEN` before invoking this function. The
    ///      assembly below reads from fixed calldata offsets (`+12` for the
    ///      next verifier, `+76` for the pqSig) inside the
    ///      `paymasterData = paymasterAndData[_PAYMASTER_DATA_OFFSET:]`
    ///      slice without internal bounds checks. If a future caller fails
    ///      to enforce the length precondition, those reads silently walk
    ///      past the calldata end, returning either zero or attacker-
    ///      controlled garbage from neighbouring calldata. The single
    ///      enforced caller today is
    ///      `validatePaymasterUserOp` — the length gate lives at the early-
    ///      return at the top of that function. Do NOT add a new caller
    ///      without replicating that gate.
    /// @param userOp The full PackedUserOperation. `paymasterAndData` must be the
    ///        complete `_PAYMASTER_AND_DATA_LEN`-byte layout (length-checked by the caller).
    /// @return valid True if the signature is valid and key rotation succeeded.
    function _verifyAndRotate(
        PackedUserOperation calldata userOp
    ) internal returns (bool valid) {
        bytes calldata paymasterData = userOp
            .paymasterAndData[_PAYMASTER_DATA_OFFSET:];

        // Offsets `+12` (validUntil 6B + validAfter 6B) and `+76`
        // (verifier 64B starts at 12) are valid ONLY because the caller has
        // already gated on `paymasterAndData.length`. See the CALLER MUST
        // block in the NatSpec above.
        WOTSPlus.WinternitzAddress calldata nextVerifier;
        WOTSPlus.WinternitzElements calldata pqSig;
        assembly {
            nextVerifier := add(paymasterData.offset, 12)
            pqSig := add(paymasterData.offset, 76)
        }

        // Reject zero-value next verifier.
        if (
            nextVerifier.publicSeed == bytes32(0) ||
            nextVerifier.publicKeyHash == bytes32(0)
        ) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.ZeroNextVerifier
            );
            return false;
        }

        WOTSPlus.WinternitzAddress storage currentVerifier = Storage
            .layout()
            .verifiers[userOp.sender];

        if (
            currentVerifier.publicSeed == bytes32(0) ||
            currentVerifier.publicKeyHash == bytes32(0)
        ) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.NoVerifierRegistered
            );
            return false;
        }

        // Reject key reuse (next must differ from current).
        if (
            nextVerifier.publicSeed == currentVerifier.publicSeed &&
            nextVerifier.publicKeyHash == currentVerifier.publicKeyHash
        ) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.NextEqualsCurrent
            );
            return false;
        }

        // Reject if `nextVerifier` is already the verifier for ANY wallet.
        // Cross-wallet reuse would let a single revealed WOTS+ signature
        // burn both wallets' verifiers — checked here so a sponsoring backend
        // bug or compromised signer can't quietly entangle two wallets via
        // the rotation path. Cheaper than WOTS+ verify, so it runs first.
        // The hash is recomputed at the end of the function rather than held
        // across the WOTS+ verify to keep the stack within solc's bounds.
        if (
            Storage.layout().verifierKeyUsed[
                _verifierHash(
                    nextVerifier.publicSeed,
                    nextVerifier.publicKeyHash
                )
            ]
        ) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.NextVerifierKeyInUse
            );
            return false;
        }

        // currentVerifier is bound explicitly because it lives in paymaster
        // storage, not in the userOp. chainId + paymaster address are bound
        // explicitly even though the latter is also present in paymasterAndData
        // — defensive layering against any future refactor of the inner hash.
        // Extracted to a helper to keep the local stack within solc's bounds
        // (the userOpBindingHash subhash alone consumes 8 slots).
        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(this)))),
            currentVerifier.publicSeed,
            currentVerifier.publicKeyHash,
            _userOpBindingHash(userOp)
        );

        if (
            !WOTSPlus.verify(
                currentVerifier,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                pqSig
            )
        ) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.InvalidSignature
            );
            return false;
        }

        // Emit before rotating so currentVerifier fields are still the old values.
        emit PqVerifierRotated(userOp.sender, currentVerifier, nextVerifier);

        // Rotate verifier and spend the new hash in the occupancy index. The
        // `currentVerifier` hash is deliberately NOT cleared: it just produced
        // a WOTS+ signature on-chain, which reveals key-chain material that
        // would let an observer forge sigs against any future re-binding of
        // the same public key. The index is monotonic — see `setPqVerifier`.
        Storage.layout().verifiers[userOp.sender] = nextVerifier;
        Storage.layout().verifierKeyUsed[
            _verifierHash(nextVerifier.publicSeed, nextVerifier.publicKeyHash)
        ] = true;

        return true;
    }

    /// @dev Hashes a WOTS+ verifier into the key used by `verifierKeyUsed`.
    ///      Two-arg `EfficientHashLib.hash` mirrors the project's preference
    ///      for solady hashing helpers over raw `keccak256`/inline asm.
    function _verifierHash(
        bytes32 publicSeed,
        bytes32 publicKeyHash
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(publicSeed, publicKeyHash);
    }

    /// @dev userOpBindingHash mirrors the field set of ERC-4337's userOpHash with
    ///      paymasterAndData truncated before the WOTS+ signature region. nextVerifier,
    ///      validUntil, validAfter, and the paymaster's own gas limits are all bound
    ///      transitively via the paymasterAndData[:_PAYMASTER_SIG_OFFSET] hash.
    ///      Extracted from `_verifyAndRotate` into its own frame to keep the
    ///      caller's local stack within solc's bounds.
    function _userOpBindingHash(
        PackedUserOperation calldata userOp
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                bytes32(uint256(uint160(userOp.sender))),
                bytes32(userOp.nonce),
                EfficientHashLib.hashCalldata(userOp.initCode),
                EfficientHashLib.hashCalldata(userOp.callData),
                userOp.accountGasLimits,
                bytes32(userOp.preVerificationGas),
                userOp.gasFees,
                EfficientHashLib.hashCalldata(
                    userOp.paymasterAndData[:_PAYMASTER_SIG_OFFSET]
                )
            );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    VIEW FUNCTIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipPaymaster
    function getPqVerifier(
        address wallet
    ) external view returns (WOTSPlus.WinternitzAddress memory) {
        return Storage.layout().verifiers[wallet];
    }

    /// @inheritdoc IQuipPaymaster
    function getDeposit() external view returns (uint256) {
        return IEntryPointStake(ENTRY_POINT).balanceOf(address(this));
    }
}
