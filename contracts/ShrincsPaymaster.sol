// Copyright (C) 2026 quip.network
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
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
// prettier-ignore
import {
    IERC7913SignatureVerifier
} from "@quip.network/hashsigs-solidity-0.2.0/contracts/interfaces/IERC7913SignatureVerifier.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
// prettier-ignore
import {
    IPaymaster,
    IEntryPointStake,
    PackedUserOperation
} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {IShrincsPaymaster} from "./interfaces/IShrincsPaymaster.sol";
import {ShrincsWalletCodec as Codec} from "./shrincs/ShrincsWalletCodec.sol";
import {ShrincsPaymasterStorage as Storage} from "./storage/ShrincsPaymasterStorage.sol";

/// @title ShrincsPaymaster
/// @notice A UUPS-upgradeable ERC-4337 verifying paymaster that authorizes gas sponsorship with a
///         single global SHRINCS stateful verifier key. The operator (sponsor) signs every userOp
///         it will pay for; the sponsorship signature is bound to the specific userOp (including
///         `userOp.sender`), so one key safely covers all wallets. Anti-replay is a
///         keyVersion-namespaced used-leaf bitmap: each leaf is consumable once, in ANY order, so
///         out-of-order userOp landing never reverts. Validation is state-changing (unlike the
///         wallet's view-only ERC-1271 path), so it consumes the leaf during validation.
///         Admin paths (`rotateStatefulKey`, `markLeavesUsed`, upgrades, treasury) are owner-fiat
///         with no PQ signature of their own: the owner is expected to be a post-quantum wallet
///         (e.g. a ShrincsWallet), which makes the whole admin surface PQ-secured upstream.
contract ShrincsPaymaster is
    IShrincsPaymaster,
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
    ///      [0:20) paymaster, [20:36) verificationGasLimit, [36:52) postOpGasLimit.
    uint256 private constant _PAYMASTER_DATA_OFFSET = 52;

    /// @dev Offset (within the [52:] custom data) where the dynamic SHRINCS blob begins.
    ///      [0:6) validUntil, [6:12) validAfter, [12:) abi.encode(PublicKey, StatefulSignature).
    uint256 private constant _CUSTOM_SIG_OFFSET = 12;

    /// @dev Offset into `paymasterAndData` past which bytes are NOT bound into the binding hash
    ///      (the dynamic SHRINCS signature material, whose PublicKey is separately pinned to the
    ///      stored commitment). Everything before it is bound. 52 + 12 = 64.
    uint256 private constant _PAYMASTER_SIG_OFFSET = 64;

    /// @dev Domain tag for the paymaster's canonical action context.
    bytes32 private constant _PAYMASTER_DOMAIN_TAG =
        keccak256("quip-shrincs-paymaster-v1");

    /// @dev `ActionContext.actionType` for sponsorship approvals.
    bytes32 private constant _ACTION_PAYMASTER_APPROVE =
        keccak256("quip.shrincs.action.paymasterApprove");

    /// @dev The pinned external SHRINCS verifier all sponsorship-signature cryptography is
    ///      delegated to (the dep's deployed `SHRINCS256sKeccak` ERC-7913 verifier — trustless:
    ///      no owner, no storage, no upgradability). Immutable, so it lives in implementation
    ///      code and is set at implementation deployment (behind the UUPS proxy).
    address public immutable SHRINCS_VERIFIER;

    constructor(address shrincsVerifier_) {
        if (shrincsVerifier_ == address(0)) revert ZeroAddressVerifier();
        SHRINCS_VERIFIER = shrincsVerifier_;
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

    /// @inheritdoc IShrincsPaymaster
    function initialize(
        address owner_,
        SHRINCS.PublicKey calldata publicKey,
        uint32 hashSuite
    ) external initializer {
        if (owner_ == address(0)) revert ZeroAddressOwner();
        // The SHRINCS library hardcodes HASH_SUITE_KECCAK_256 into every canonical message
        // hash, so the declared suite is a client-agreement check, not a dispatch choice.
        if (hashSuite != HashSuite.HASH_SUITE_ID)
            revert UnsupportedHashSuite();

        // Validate the supplied bundle's fixed shape and its embedded commitment
        // (validPublicKey checks the embedded commitment recomputes), then derive the
        // leaf budget from the key bytes — like `rotateStatefulKey` and the wallet's
        // `initialize`, the budget is never a trusted free parameter.
        if (!SHRINCS.validPublicKey(publicKey)) revert CommitmentMismatch();
        bytes32 commitment = bytes32(publicKey.publicKeyCommitment[:32]);
        (UXMSS.StatefulPublicKey memory decoded, bool ok) = SHRINCS
            .decodeStatefulPublicKey(publicKey.statefulPublicKey);
        if (!ok || decoded.maxSignatures == 0) revert ZeroMaxSignatures();

        _initializeOwner(owner_);

        Storage.Layout storage $ = Storage.layout();
        // The initial verifier occupies epoch 0; the paymaster always has a verifier from here on.
        // statefulLeavesUsed and the leaf bitmap start empty by default.
        $.shrincsCommitment = commitment;
        $.maxSignatures = decoded.maxSignatures;

        emit PaymasterInitialized(owner_);
        emit ShrincsVerifierSet(
            bytes32(0),
            commitment,
            hashSuite,
            decoded.maxSignatures,
            0
        );
    }

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 /* userOpHash */,
        uint256 /* maxCost */
    ) external override returns (bytes memory context, uint256 validationData) {
        if (msg.sender != ENTRY_POINT) revert InvalidEntryPoint();

        // Need at least the header + validUntil/validAfter + a minimal ABI head for the blob.
        if (
            userOp.paymasterAndData.length <
            _PAYMASTER_DATA_OFFSET + _CUSTOM_SIG_OFFSET + 0x40
        ) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.MalformedPayload
            );
            return ("", 1);
        }

        if (!_verifyAndAdvance(userOp)) return ("", 1);

        bytes calldata paymasterData = userOp
            .paymasterAndData[_PAYMASTER_DATA_OFFSET:];
        uint48 validUntil = uint48(bytes6(paymasterData[:6]));
        uint48 validAfter = uint48(bytes6(paymasterData[6:12]));
        validationData =
            (uint256(validUntil) << 160) |
            (uint256(validAfter) << 208);
        context = abi.encode(userOp.sender);
    }

    /// @inheritdoc IPaymaster
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

    /// @inheritdoc IShrincsPaymaster
    function rotateStatefulKey(
        SHRINCS.PublicKey calldata currentPublicKey,
        SHRINCS.StatefulRotationTarget calldata nextStatefulKey
    ) external onlyOwner {
        Storage.Layout storage $ = Storage.layout();

        // Pin the presented current bundle to the installed commitment so its stateless half
        // (pkSeed, hypertreeRoot) is trustworthy to carry into the next bundle. The stateless
        // half is never rotated here: only stateful sponsorship signatures are ever verified,
        // so the stateless side is inert key identity.
        if (
            !SHRINCS.validPublicKey(currentPublicKey) ||
            !SHRINCS.matchesExpectedPublicKeyCommitment(
                currentPublicKey,
                $.shrincsCommitment
            )
        ) revert CommitmentMismatch();

        if (
            nextStatefulKey.statefulPublicKey.length !=
            SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES
        ) revert CommitmentMismatch();
        (UXMSS.StatefulPublicKey memory decoded, bool ok) = SHRINCS
            .decodeStatefulPublicKey(nextStatefulKey.statefulPublicKey);
        if (!ok || decoded.maxSignatures == 0) revert ZeroMaxSignatures();

        bytes32 nextCommitment = SHRINCS.publicKeyCommitmentFromParts(
            nextStatefulKey.statefulPublicKey,
            currentPublicKey.pkSeed,
            currentPublicKey.hypertreeRoot
        );
        // Fiat rotation carries no authorizing signature over the next commitment (unlike the
        // wallet's `rotateKey`, whose PQ signature covers it): the owner is expected to be a
        // post-quantum wallet (e.g. a ShrincsWallet), so this call is already PQ-authorized
        // upstream, and the current-bundle pin above makes rotation compare-and-swap (a replay
        // fails the pin once the installed commitment changes — no rotation nonce needed). The
        // declared target commitment is the operator's statement of intent and MUST match the
        // recomputed one end-to-end.
        if (
            nextStatefulKey.publicKeyCommitment.length != 32 ||
            bytes32(nextStatefulKey.publicKeyCommitment[:32]) != nextCommitment
        ) revert CommitmentMismatch();

        bytes32 previous = $.shrincsCommitment;
        // keyVersion is monotonic: always bump, never reset. A fresh epoch gives a fresh (empty)
        // leaf-bitmap namespace so the rotated key starts from no consumed leaves.
        uint256 nextEpoch = $.keyVersion + 1;

        $.shrincsCommitment = nextCommitment;
        $.maxSignatures = decoded.maxSignatures;
        $.statefulLeavesUsed = 0;
        $.keyVersion = nextEpoch;

        emit KeyRotated(
            previous,
            nextCommitment,
            nextEpoch,
            decoded.maxSignatures
        );
    }

    /// @inheritdoc IShrincsPaymaster
    function markLeavesUsed(uint32[] calldata leaves) external onlyOwner {
        if (leaves.length == 0) revert EmptyLeaves();

        Storage.Layout storage $ = Storage.layout();
        uint256 epoch = $.keyVersion;
        uint256 n = leaves.length;
        // Idempotent Effects only: already-used targets (including duplicates within the batch)
        // are skipped, not reverted — a sponsorship racing its own revocation must not brick the
        // batch. Out-of-range is a client bug, not a race — fail the whole batch loudly.
        for (uint256 i = 0; i < n; ++i) {
            uint32 leaf = leaves[i];
            if (leaf == 0 || leaf > $.maxSignatures)
                revert LeafOutOfRange(leaf);
            if (_isStatefulLeafUsed($, epoch, leaf)) {
                emit LeafRevocationSkipped(leaf, epoch);
                continue;
            }
            _markStatefulLeafUsed($, epoch, leaf);
            unchecked {
                // Bounded by `maxSignatures`: every mark is a unique in-range leaf.
                $.statefulLeavesUsed += 1;
            }
            emit LeafRevoked(leaf, epoch);
        }
    }

    /// @inheritdoc IShrincsPaymaster
    function deposit() external payable {
        IEntryPointStake(ENTRY_POINT).depositTo{value: msg.value}(
            address(this)
        );
    }

    /// @inheritdoc IShrincsPaymaster
    function withdrawTo(address payable to, uint256 amount) external onlyOwner {
        IEntryPointStake(ENTRY_POINT).withdrawTo(to, amount);
    }

    /// @inheritdoc IShrincsPaymaster
    function addStake(uint32 unstakeDelaySec) external payable onlyOwner {
        IEntryPointStake(ENTRY_POINT).addStake{value: msg.value}(
            unstakeDelaySec
        );
    }

    /// @inheritdoc IShrincsPaymaster
    function unlockStake() external onlyOwner {
        IEntryPointStake(ENTRY_POINT).unlockStake();
    }

    /// @inheritdoc IShrincsPaymaster
    function withdrawStake(address payable to) external onlyOwner {
        IEntryPointStake(ENTRY_POINT).withdrawStake(to);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  INTERNAL FUNCTIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Verifies the global SHRINCS stateful sponsorship signature and consumes its leaf in the
    ///      used-leaf bitmap. The consume is committed immediately (the anti-replay Effect), so the
    ///      leaf is spent regardless of whether execution later succeeds. No wrapper nonce is bound:
    ///      anti-replay is the one-time leaf, and freshness comes from `userOp.nonce` (already inside
    ///      `_userOpBindingHash`), so sponsored userOps may land in any order.
    function _verifyAndAdvance(
        PackedUserOperation calldata userOp
    ) internal returns (bool) {
        // The verifier is set at `initialize` and can only be rotated, never unset, so
        // `commitment` is always non-zero here.
        Storage.Layout storage $ = Storage.layout();
        bytes32 commitment = $.shrincsCommitment;

        bytes calldata blob = userOp.paymasterAndData[_PAYMASTER_DATA_OFFSET +
            _CUSTOM_SIG_OFFSET:];
        (
            SHRINCS.PublicKey calldata pk,
            SHRINCS.Signature calldata sig
        ) = Codec.decodeSponsorshipSignature(blob);

        uint256 epoch = $.keyVersion;
        uint32 leaf = uint32(sig.authPath.length);
        if (leaf == 0 || leaf > $.maxSignatures) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.StatefulBudgetExhausted
            );
            return false;
        }
        if (_isStatefulLeafUsed($, epoch, leaf)) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.StaleStatefulLeaf
            );
            return false;
        }

        SHRINCS.ActionContext memory ctx = SHRINCS.ActionContext({
            domainSeparator: _domainSeparator(),
            nonce: 0,
            keyVersion: epoch,
            actionType: _ACTION_PAYMASTER_APPROVE,
            payloadHash: _userOpBindingHash(userOp)
        });

        // Stateful verification via the pinned ERC-7913 verifier, in lock-step with the
        // wallet's `_tryVerifyStateful`
        bool sponsorshipValid;
        try
            IERC7913SignatureVerifier(SHRINCS_VERIFIER).verify(
                abi.encodePacked(commitment),
                SHRINCS.statefulActionMessageHash(commitment, ctx),
                abi.encode(pk, sig)
            )
        returns (bytes4 result) {
            sponsorshipValid =
                result == IERC7913SignatureVerifier.verify.selector;
        } catch {
            sponsorshipValid = false;
        }
        if (!sponsorshipValid) {
            emit PaymasterValidationRejected(
                userOp.sender,
                PaymasterValidationFailure.InvalidSignature
            );
            return false;
        }

        // EFFECT (anti-replay): consume the leaf.
        _markStatefulLeafUsed($, epoch, leaf);
        unchecked {
            $.statefulLeavesUsed += 1;
        }
        emit SponsorshipVerified(userOp.sender, leaf, epoch);
        return true;
    }

    /// @dev Returns whether stateful `leafIndex` has been consumed in the given verifier epoch.
    function _isStatefulLeafUsed(
        Storage.Layout storage $,
        uint256 keyVersion_,
        uint256 leafIndex
    ) internal view returns (bool) {
        return
            ($.usedStatefulLeafBitmap[keyVersion_][leafIndex >> 8] &
                (uint256(1) << (leafIndex & 0xff))) != 0;
    }

    /// @dev Marks stateful `leafIndex` consumed in the given verifier epoch.
    function _markStatefulLeafUsed(
        Storage.Layout storage $,
        uint256 keyVersion_,
        uint256 leafIndex
    ) internal {
        $.usedStatefulLeafBitmap[keyVersion_][leafIndex >> 8] |=
            uint256(1) <<
            (leafIndex & 0xff);
    }

    /// @dev The paymaster's canonical signing domain: tag + chainId + this paymaster.
    function _domainSeparator() internal view returns (bytes32) {
        return
            EfficientHashLib.hash(
                _PAYMASTER_DOMAIN_TAG,
                bytes32(block.chainid),
                bytes32(uint256(uint160(address(this))))
            );
    }

    /// @dev Binds the userOp's field set (mirroring ERC-4337's userOpHash) with
    ///      `paymasterAndData` truncated before the SHRINCS signature region (which is excluded
    ///      to break the circular dependency; the embedded PublicKey is separately pinned to the
    ///      stored commitment). Backend signers MUST replicate this construction.
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

    /// @inheritdoc IShrincsPaymaster
    function getShrincsVerifier()
        external
        view
        returns (
            bytes32 commitment,
            uint32 hashSuite,
            uint256 keyVersion,
            uint32 maxSignatures,
            uint32 statefulLeavesUsed
        )
    {
        Storage.Layout storage $ = Storage.layout();
        // The hash suite is not stored: registration rejects anything but
        // HASH_SUITE_KECCAK_256, so the installed suite is always the constant.
        return (
            $.shrincsCommitment,
            HashSuite.HASH_SUITE_ID,
            $.keyVersion,
            $.maxSignatures,
            $.statefulLeavesUsed
        );
    }

    /// @inheritdoc IShrincsPaymaster
    function isStatefulLeafUsed(uint256 leaf) external view returns (bool) {
        Storage.Layout storage $ = Storage.layout();
        return _isStatefulLeafUsed($, $.keyVersion, leaf);
    }

    /// @inheritdoc IShrincsPaymaster
    function remainingStatefulSignatures() external view returns (uint32) {
        Storage.Layout storage $ = Storage.layout();
        if ($.statefulLeavesUsed >= $.maxSignatures) return 0;
        return $.maxSignatures - $.statefulLeavesUsed;
    }

    /// @inheritdoc IShrincsPaymaster
    function getDeposit() external view returns (uint256) {
        return IEntryPointStake(ENTRY_POINT).balanceOf(address(this));
    }
}
