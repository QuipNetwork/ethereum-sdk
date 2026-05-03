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
import {IPaymaster, IEntryPointStake, PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
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
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          CONSTANTS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev ERC-4337 v0.7 EntryPoint singleton address.
    address public constant ENTRY_POINT =
        0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    /// @dev Offset into `paymasterAndData` where custom paymaster data begins.
    ///      [0:20) paymaster address, [20:36) verificationGasLimit, [36:52) postOpGasLimit.
    uint256 private constant _PAYMASTER_DATA_OFFSET = 52;

    /// @dev Domain tag for paymaster approval digests (WOTS+ domain-tagged, not EIP-712).
    bytes32 private constant _PAYMASTER_APPROVE_TAG =
        keccak256("quip.digest.paymasterApprove");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTRUCTOR                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    constructor() {
        _disableInitializers();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTERNAL OVERRIDES                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Guard owner initialization to prevent re-initialization.
    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }

    /// @dev Restrict upgrades to the contract owner.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      EXTERNAL FUNCTIONS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipPaymaster
    function initialize(address owner_) external initializer {
        if (owner_ == address(0)) revert ZeroAddressOwner();
        _initializeOwner(owner_);
        emit PaymasterInitialized(owner_);
    }

    /// @inheritdoc IPaymaster
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 /* maxCost */
    ) external override returns (bytes memory context, uint256 validationData) {
        if (msg.sender != ENTRY_POINT) revert InvalidEntryPoint();

        // Decode custom paymaster data from paymasterAndData[52:].
        // [0:6)     validUntil (uint48)
        // [6:12)    validAfter (uint48)
        // [12:76)   nextVerifier (WinternitzAddress: 32 bytes publicSeed + 32 bytes publicKeyHash)
        // [76:2220) WOTS+ signature (67 × 32 = 2144 bytes)
        bytes calldata paymasterData = userOp
            .paymasterAndData[_PAYMASTER_DATA_OFFSET:];

        if (
            !_verifyAndRotate(
                userOp.sender,
                userOp.nonce,
                userOp.callData,
                paymasterData
            )
        ) return ("", 1);

        // Pack validationData: [0:160) authorizer=0, [160:208) validUntil, [208:256) validAfter.
        uint48 validUntil = uint48(bytes6(paymasterData[:6]));
        uint48 validAfter = uint48(bytes6(paymasterData[6:12]));
        validationData =
            (uint256(validUntil) << 160) |
            (uint256(validAfter) << 208);
        context = "";
    }

    /// @inheritdoc IPaymaster
    function postOp(
        PostOpMode,
        bytes calldata,
        uint256,
        uint256
    ) external override {
        if (msg.sender != ENTRY_POINT) revert InvalidEntryPoint();
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
        $.verifiers[wallet] = verifier;
        emit PqVerifierSet(wallet, verifier);
    }

    /// @inheritdoc IQuipPaymaster
    function removePqVerifier(address wallet) external onlyOwner {
        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress storage existing = $.verifiers[wallet];
        if (
            existing.publicSeed == bytes32(0) &&
            existing.publicKeyHash == bytes32(0)
        ) revert PqVerifierNotRegistered();

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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNAL FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Verifies the WOTS+ signature and rotates the per-wallet verifier key.
    ///      Rotation is committed immediately so the key is rotated regardless of whether
    ///      the execution phase succeeds or fails. This is critical because WOTS+ is a
    ///      one-time signature scheme — the signing key is effectively compromised once
    ///      the signature is revealed on-chain.
    ///
    ///      The digest is built from constituent UserOp fields (sender, nonce, callData).
    /// @param sender The wallet address (userOp.sender).
    /// @param nonce The UserOp nonce.
    /// @param callData_ The UserOp callData.
    /// @param paymasterData The paymaster data slice starting after the 52-byte header.
    /// @return valid True if the signature is valid and key rotation succeeded.
    function _verifyAndRotate(
        address sender,
        uint256 nonce,
        bytes calldata callData_,
        bytes calldata paymasterData
    ) internal returns (bool valid) {
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
                sender,
                PaymasterValidationFailure.ZeroNextVerifier
            );
            return false;
        }

        WOTSPlus.WinternitzAddress storage currentVerifier = Storage
            .layout()
            .verifiers[sender];

        // Reject if no verifier set for this wallet.
        if (
            currentVerifier.publicSeed == bytes32(0) &&
            currentVerifier.publicKeyHash == bytes32(0)
        ) {
            emit PaymasterValidationRejected(
                sender,
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
                sender,
                PaymasterValidationFailure.NextEqualsCurrent
            );
            return false;
        }

        // Build domain-tagged digest from constituent UserOp fields.
        // Using an intermediate opCommitment avoids exceeding EfficientHashLib's 8-arg limit.
        bytes32 opCommitment = EfficientHashLib.hash(
            bytes32(uint256(uint160(sender))),
            bytes32(nonce),
            EfficientHashLib.hashCalldata(callData_)
        );

        bytes32 digest = EfficientHashLib.hash(
            _PAYMASTER_APPROVE_TAG,
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(this)))),
            currentVerifier.publicSeed,
            currentVerifier.publicKeyHash,
            nextVerifier.publicSeed,
            nextVerifier.publicKeyHash,
            opCommitment
        );

        if (
            !WOTSPlus.verify(
                currentVerifier,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                pqSig
            )
        ) {
            emit PaymasterValidationRejected(
                sender,
                PaymasterValidationFailure.InvalidSignature
            );
            return false;
        }

        // Emit before rotating so currentVerifier fields are still the old values.
        emit PqVerifierRotated(sender, currentVerifier, nextVerifier);

        // Rotate verifier.
        Storage.layout().verifiers[sender] = nextVerifier;

        return true;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       VIEW FUNCTIONS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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
