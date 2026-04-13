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

import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {UUPSUpgradeable} from "solady-0.1.26/src/utils/UUPSUpgradeable.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {SafeTransferLib} from "solady-0.1.26/src/utils/SafeTransferLib.sol";
import {LibCall} from "solady-0.1.26/src/utils/LibCall.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "./interfaces/IQuipWallet.sol";
import {IQuipFactory} from "./interfaces/IQuipFactory.sol";
import {WOTSPlusCodec as Codec} from "./WOTSPlusCodec.sol";
import {WOTSPlusStorage as Storage} from "./storage/WOTSPlusStorage.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "./libraries/EnumerableWinternitzAddressSet.sol";

/// @title QuipWallet
contract QuipWallet is IQuipWallet, ERC4337, Initializable {
    using EnumerableSetLib for EnumerableSetLib.Bytes32Set;
    using Keyset for Keyset.WinternitzAddressSet;

    uint256 public constant MAX_KEYS = 10;
    address payable public immutable FACTORY;

    /// @dev uint256(keccak256("quip.wallet.upgrade.guard")) - 1
    /// Transient storage slot used to gate `migrate` to the `upgradeToAndCall` context.
    /// @notice REQUIRES EIP-1153 (transient storage opcodes TSTORE/TLOAD).
    uint256 private constant _UPGRADE_GUARD_SLOT =
        0x490d87f9a8524f6238d75626265800824e3fa88e60bc82c13f11bbd9042ed677;

    /// @dev PQ storage base slot (ERC-7201 namespace: quip.storage.wallet.wotsplus).
    /// quipFactory at base+0, pqOwner.publicSeed at base+1, pqOwner.publicKeyHash at base+2.
    bytes32 private constant _PQ_FACTORY_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;
    bytes32 private constant _PQ_OWNER_SEED_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf701;
    bytes32 private constant _PQ_OWNER_HASH_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf702;

    constructor(address payable factory_) {
        if (factory_ == address(0)) revert ZeroAddressFactory();
        FACTORY = factory_;
        _disableInitializers();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    INTERNAL OVERRIDES                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev EIP-712 domain name and version for ERC-1271 signature validation.
    function _domainNameAndVersion()
        internal
        pure
        override
        returns (string memory name, string memory version)
    {
        name = "QuipWallet";
        version = "1";
    }

    /// @dev WOTS+ signature validation for ERC-4337 UserOps.
    /// Decodes a WOTS+ one-time signature and the caller-supplied nextPqOwner from
    /// `userOp.signature`, then verifies the signature against the current `pqOwner`.
    ///
    /// Validation fails (returns 1) when:
    ///   - `nextPqOwner` is zero (missing key material).
    ///   - `nextPqOwner` equals the current `pqOwner` (key reuse / no rotation).
    ///   - The WOTS+ signature does not verify against the current `pqOwner`.
    ///
    /// On success the key rotation is committed immediately via `_rotatePqOwner`.
    /// The EntryPoint's `handleOps` invokes validation and execution as two separate
    /// top-level calls on the account within the same transaction. Writing the rotation
    /// during validation ensures the key is rotated
    /// regardless of whether the execution phase succeeds or fails.
    ///
    /// Security: because WOTS+ is a one-time signature scheme, the signing key is
    /// effectively compromised once the signature is revealed on-chain in the UserOp.
    /// It is therefore imperative that key rotation succeeds regardless of whether the
    /// inner execution call succeeds or fails.
    ///
    /// @param userOp  The packed ERC-4337 user operation.
    /// @param userOpHash  Hash of the user operation produced by the EntryPoint.
    /// @return validationData  0 if the signature is valid, 1 otherwise.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256 validationData) {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeUserOpSignature(userOp.signature);

        if (nextPqOwner.publicSeed == bytes32(0) || nextPqOwner.publicKeyHash == bytes32(0))
            return 1;

        Storage.Layout storage $ = Storage.layout();

        if (
            nextPqOwner.publicSeed == $.pqOwner.publicSeed &&
            nextPqOwner.publicKeyHash == $.pqOwner.publicKeyHash
        ) return 1;

        bytes32 digest = Codec.erc4337ExecuteDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            userOpHash,
            getExecuteFee()
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            return 1;

        _rotatePqOwner(nextPqOwner);

        return 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   ERC-4337 EXECUTION                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc ERC4337
    /// @dev Key rotation is committed during `_validateSignature`.
    /// Fee is only collected on success — if the inner call reverts, the entire
    /// execution phase rolls back (including the fee transfer). The EntryPoint
    /// still deducts gas costs from the wallet's prefund deposit.
    /// Owner must use `execute(bytes)` which has inline PQ auth.
    function execute(address target, uint256 value, bytes calldata data)
        public
        payable
        override
        onlyEntryPoint
        returns (bytes memory result)
    {
        uint256 fee = getExecuteFee();
        if (fee > 0 && address(this).balance >= fee) {
            SafeTransferLib.safeTransferETH(Storage.layout().quipFactory, fee);
        }
        result = super.execute(target, value, data);
    }

    /// @inheritdoc ERC4337
    /// @dev Key rotation is committed during `_validateSignature`.
    /// Fee is only collected on success — if any call in the batch reverts,
    /// the entire execution phase rolls back (including the fee transfer).
    function executeBatch(Call[] calldata calls)
        public
        payable
        override
        onlyEntryPoint
        returns (bytes[] memory results)
    {
        uint256 fee = getExecuteFee();
        if (fee > 0 && address(this).balance >= fee) {
            SafeTransferLib.safeTransferETH(Storage.layout().quipFactory, fee);
        }
        results = super.executeBatch(calls);
    }

    /// @inheritdoc ERC4337
    /// @dev Key rotation is committed during `_validateSignature`.
    /// Fee is only collected on success — if the delegatecall reverts, the entire
    /// execution phase rolls back (including the fee transfer).
    function delegateExecute(address delegate, bytes calldata data)
        public
        payable
        override
        onlyEntryPoint
        delegateExecuteGuard
        returns (bytes memory result)
    {
        uint256 fee = getExecuteFee();
        if (fee > 0 && address(this).balance >= fee) {
            SafeTransferLib.safeTransferETH(Storage.layout().quipFactory, fee);
        }
        result = super.delegateExecute(delegate, data);
    }

    /// @inheritdoc ERC4337
    /// @dev Key rotation is committed during `_validateSignature`.
    function storageStore(bytes32 storageSlot, bytes32 storageValue)
        public
        payable
        override
        onlyEntryPoint
        storageStoreGuard(storageSlot)
    {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(storageSlot, storageValue)
        }
    }

    /// @dev Extends Solady's guard with PQ-specific protected slots.
    modifier storageStoreGuard(bytes32 storageSlot) override {
        /// @solidity memory-safe-assembly
        assembly {
            if or(
                or(eq(storageSlot, _OWNER_SLOT), eq(storageSlot, _ERC1967_IMPLEMENTATION_SLOT)),
                or(
                    eq(storageSlot, _PQ_FACTORY_SLOT),
                    or(eq(storageSlot, _PQ_OWNER_SEED_SLOT), eq(storageSlot, _PQ_OWNER_HASH_SLOT))
                )
            ) {
                revert(codesize(), 0x00)
            }
        }
        _;
    }

    /// @dev Extends Solady's guard with PQ-specific protected slots.
    modifier delegateExecuteGuard() override {
        bytes32 ownerValue;
        bytes32 implValue;
        bytes32 factoryValue;
        bytes32 seedValue;
        bytes32 hashValue;
        /// @solidity memory-safe-assembly
        assembly {
            ownerValue := sload(_OWNER_SLOT)
            implValue := sload(_ERC1967_IMPLEMENTATION_SLOT)
            factoryValue := sload(_PQ_FACTORY_SLOT)
            seedValue := sload(_PQ_OWNER_SEED_SLOT)
            hashValue := sload(_PQ_OWNER_HASH_SLOT)
        }
        _;
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(
                and(
                    and(
                        eq(ownerValue, sload(_OWNER_SLOT)),
                        eq(implValue, sload(_ERC1967_IMPLEMENTATION_SLOT))
                    ),
                    and(
                        eq(factoryValue, sload(_PQ_FACTORY_SLOT)),
                        and(
                            eq(seedValue, sload(_PQ_OWNER_SEED_SLOT)),
                            eq(hashValue, sload(_PQ_OWNER_HASH_SLOT))
                        )
                    )
                )
            ) { revert(codesize(), 0x00) }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          PUBLIC                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipWallet
    function renounceOwnership() public payable override(IQuipWallet, Ownable) onlyOwner {
        revert RenounceDisabled();
    }

    /// @dev Blocks the classical `transferOwnership(address)`.
    ///      All ownership transfers MUST go through the WOTS+-authenticated `transferOwnership(bytes)`.
    function transferOwnership(address) public payable override {
        revert ClassicalTransferOwnershipDisabled();
    }

    /// @dev Blocks the classical `completeOwnershipHandover(address)`.
    ///      All handovers MUST go through the WOTS+-authenticated `completeOwnershipHandover(bytes)`.
    function completeOwnershipHandover(address) public payable override {
        revert ClassicalCompleteOwnershipHandoverDisabled();
    }

    /// @inheritdoc IQuipWallet
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) public initializer {
        if (msg.sender != FACTORY) revert InvalidFactory();
        if (newOwner == address(0)) revert ZeroAddressOwner();

        (
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        ) = Codec.decodeInit(payload);
        _enforceNonZeroPqOwner(newPqOwner);

        _initializeOwner(newOwner);
        Storage.Layout storage $ = Storage.layout();
        $.quipFactory = FACTORY;
        $.pqOwner = newPqOwner;

        _addRecoveryKeys(recoveryKeys);
        _verifyInitialState();

        emit WalletInitialized(FACTORY, newOwner, newPqOwner, recoveryKeys);
    }

    /// @inheritdoc IQuipWallet
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) public payable override(IQuipWallet, UUPSUpgradeable) onlyOwner {
        // Vet implementation locally BEFORE any delegatecall.
        bytes32 implCodehash = newImplementation.codehash;
        IQuipFactory factory = IQuipFactory(FACTORY);
        if (factory.getVettedCodeIndex(implCodehash) == type(uint256).max)
            revert ImplementationNotVetted();
        if (factory.deprecatedImpls(implCodehash))
            revert ImplementationDeprecated();

        Storage.Layout storage $ = Storage.layout();
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeUpgradeAuth(data);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);

        bytes32 digest = Codec.upgradeDigest(
            address(this),
            block.chainid,
            newImplementation,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(this.verifyUpgrade, (newImplementation, data))
        );

        _rotatePqOwner(nextPqOwner);

        (bool shouldMigrate, bytes calldata migratorPayload) = Codec.decodeUpgradeMigration(data);
        if (shouldMigrate) {
            uint256 slot = _UPGRADE_GUARD_SLOT;
            assembly { tstore(slot, 1) }
            // abi.encodeCall re-serializes migratorPayload into fresh calldata,
            // so migrate's decodeInit reads from offset 0 of the init layout
            // regardless of where the slice sat in the original upgrade payload.
            LibCall.delegateCallContract(
                newImplementation,
                abi.encodeCall(this.migrate, (migratorPayload))
            );
            assembly { tstore(slot, 0) }
        }

        super.upgradeToAndCall(newImplementation, data[0:0]);
    }

    /// @inheritdoc IQuipWallet
    function changePqOwner(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeChangePqOwner(payload);

        _enforceNonZeroPqOwner(newPqOwner);
        _enforceDifferentPqOwner(newPqOwner);

        Storage.Layout storage $ = Storage.layout();
        bytes32 digest = Codec.keyRotationDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            newPqOwner.publicSeed,
            newPqOwner.publicKeyHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        _rotatePqOwner(newPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function execute(bytes calldata payload) public payable onlyOwner returns (bytes memory) {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            address target,
            uint256 value,
            bytes calldata data
        ) = Codec.decodeExecute(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);

        uint256 fee = getExecuteFee();
        if (address(this).balance < value + fee)
            revert InsufficientBalance(value + fee, address(this).balance);

        Storage.Layout storage $ = Storage.layout();
        bytes32 dataHash = EfficientHashLib.hashCalldata(data);
        bytes32 digest = Codec.executeDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            target,
            value,
            dataHash,
            fee
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        _rotatePqOwner(nextPqOwner);

        if (fee > 0) SafeTransferLib.safeTransferETH($.quipFactory, fee);

        bytes memory result;
        if (data.length == 0) {
            if (value > 0) SafeTransferLib.safeTransferETH(target, value);
        } else {
            result = LibCall.callContract(target, value, data);
        }

        emit ExecutionSucceeded(target, value, dataHash);

        return result;
    }

    /// @dev Blocks the classical ERC-4337 `withdrawDepositTo(address,uint256)`.
    ///      All withdrawals MUST go through the WOTS+-authenticated `withdrawDepositTo(bytes)`.
    function withdrawDepositTo(address, uint256) public payable override {
        revert ClassicalWithdrawDisabled();
    }

    /// @inheritdoc IQuipWallet
    function withdrawDepositTo(bytes calldata payload) public payable onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            address to,
            uint256 amount
        ) = Codec.decodeWithdrawDeposit(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);

        Storage.Layout storage $ = Storage.layout();
        bytes32 digest = Codec.withdrawDepositDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            to,
            amount
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        _rotatePqOwner(nextPqOwner);

        ERC4337.withdrawDepositTo(to, amount);
    }

    /// @inheritdoc IQuipWallet
    function transferOwnership(bytes calldata payload) public payable onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            address newOwner
        ) = Codec.decodeOwnershipTransfer(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);

        Storage.Layout storage $ = Storage.layout();
        bytes32 digest = Codec.transferOwnershipDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            newOwner
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        _rotatePqOwner(nextPqOwner);

        Ownable.transferOwnership(newOwner);
    }

    /// @inheritdoc IQuipWallet
    function completeOwnershipHandover(bytes calldata payload) public payable onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            address pendingOwner
        ) = Codec.decodeOwnershipTransfer(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);

        Storage.Layout storage $ = Storage.layout();
        bytes32 digest = Codec.completeOwnershipHandoverDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            pendingOwner
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        _rotatePqOwner(nextPqOwner);

        Ownable.completeOwnershipHandover(pendingOwner);
    }

    /// @inheritdoc IQuipWallet
    function recoverWallet(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata recoveryKey,
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeRecoverWallet(payload);

        Storage.Layout storage $ = Storage.layout();
        bytes32 keyHash = EfficientHashLib.hash(recoveryKey.publicSeed, recoveryKey.publicKeyHash);
        if (!$.recoveryKeyHashes.contains(keyHash))
            revert RecoveryKeyNotFound();

        _enforceNonZeroPqOwner(newPqOwner);
        _enforceDifferentPqOwner(newPqOwner);

        bytes32 digest = Codec.keyRotationDigest(
            address(this),
            block.chainid,
            recoveryKey.publicSeed,
            recoveryKey.publicKeyHash,
            newPqOwner.publicSeed,
            newPqOwner.publicKeyHash
        );

        if (!WOTSPlus.verify(recoveryKey, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        $.recoveryKeyHashes.remove(keyHash);
        _rotatePqOwner(newPqOwner);

        emit PqRecovery(recoveryKey, newPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function addRecoveryKeys(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
        ) = Codec.decodeKeyManagement(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);
        if (getRecoveryKeyCount() + newRecoveryKeys.length > MAX_KEYS)
            revert RecoveryKeyLimitExceeded();

        Storage.Layout storage $ = Storage.layout();
        bytes32 keysHash = EfficientHashLib.hash(abi.encode(newRecoveryKeys));
        bytes32 digest = Codec.keyManagementDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            keysHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        _addRecoveryKeys(newRecoveryKeys);

        _rotatePqOwner(nextPqOwner);

        emit RecoveryKeysAdded(nextPqOwner, newRecoveryKeys.length);
    }

    /// @inheritdoc IQuipWallet
    function replenishRecoveryKeys(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
        ) = Codec.decodeKeyManagement(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);
        if (newRecoveryKeys.length > MAX_KEYS)
            revert RecoveryKeyLimitExceeded();

        Storage.Layout storage $ = Storage.layout();
        bytes32 keysHash = EfficientHashLib.hash(abi.encode(newRecoveryKeys));
        bytes32 digest = Codec.keyManagementDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            keysHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        uint256 clearLen = $.recoveryKeyHashes.length();
        for (uint256 i = 0; i < clearLen; ++i) {
            $.recoveryKeyHashes.remove($.recoveryKeyHashes.at(0));
        }

        _addRecoveryKeys(newRecoveryKeys);

        _rotatePqOwner(nextPqOwner);

        emit RecoveryKeysReplenished(nextPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function addVerificationKeys(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata newKeys
        ) = Codec.decodeKeyManagement(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);
        if (newKeys.length == 0) revert EmptyVerificationKeys();

        Storage.Layout storage $ = Storage.layout();
        if ($.verificationKeyset.length() + newKeys.length > MAX_KEYS)
            revert VerificationKeyLimitExceeded();

        bytes32 keysHash = EfficientHashLib.hash(abi.encode(newKeys));
        bytes32 digest = Codec.verificationKeysetDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            keysHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        _addVerificationKeys(newKeys);

        _rotatePqOwner(nextPqOwner);

        emit VerificationKeysAdded(nextPqOwner, newKeys.length);
    }

    /// @inheritdoc IQuipWallet
    function refreshVerificationKeyset(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata newKeys
        ) = Codec.decodeKeyManagement(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);
        if (newKeys.length == 0) revert EmptyVerificationKeys();
        if (newKeys.length > MAX_KEYS) revert VerificationKeyLimitExceeded();

        Storage.Layout storage $ = Storage.layout();
        bytes32 keysHash = EfficientHashLib.hash(abi.encode(newKeys));
        bytes32 digest = Codec.verificationKeysetDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            keysHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        uint256 clearLen = $.verificationKeyset.length();
        for (uint256 i = 0; i < clearLen; ++i) {
            WOTSPlus.WinternitzAddress memory existing = $.verificationKeyset.at(0);
            $.verificationKeyset.remove(existing);
        }

        _addVerificationKeys(newKeys);

        _rotatePqOwner(nextPqOwner);

        emit VerificationKeysetRefreshed(nextPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function replaceVerificationKeyAt(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            uint256 index,
            WOTSPlus.WinternitzAddress calldata newKey
        ) = Codec.decodeVerificationKeysetReplace(payload);

        _enforceNonZeroPqOwner(nextPqOwner);
        _enforceDifferentPqOwner(nextPqOwner);
        if (newKey.publicSeed == bytes32(0) || newKey.publicKeyHash == bytes32(0))
            revert ZeroValuePqOwner();

        Storage.Layout storage $ = Storage.layout();
        if (index >= $.verificationKeyset.length())
            revert VerificationKeyIndexOutOfBounds();

        WOTSPlus.WinternitzAddress memory oldKey = $.verificationKeyset.at(index);

        bytes32 digest = Codec.verificationKeysetReplaceDigest(
            address(this),
            block.chainid,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash,
            index,
            newKey.publicSeed,
            newKey.publicKeyHash
        );

        if (!WOTSPlus.verify($.pqOwner, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        $.verificationKeyset.remove(oldKey);
        if (!$.verificationKeyset.add(newKey)) revert DuplicateVerificationKey();

        _rotatePqOwner(nextPqOwner);

        emit VerificationKeyReplaced(index, oldKey, newKey, nextPqOwner);
    }

    /// @inheritdoc IQuipWallet
    function recoveryUpgrade(address newImplementation, bytes calldata payload) public onlyOwner {
        // Vet implementation locally BEFORE any delegatecall.
        bytes32 implCodehash = newImplementation.codehash;
        IQuipFactory factory = IQuipFactory(FACTORY);
        if (factory.getVettedCodeIndex(implCodehash) == type(uint256).max)
            revert ImplementationNotVetted();
        if (factory.deprecatedImpls(implCodehash))
            revert ImplementationDeprecated();
        (
            WOTSPlus.WinternitzAddress calldata recoveryKey,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeUpgradeAuth(payload);

        Storage.Layout storage $ = Storage.layout();

        bytes32 keyHash = EfficientHashLib.hash(recoveryKey.publicSeed, recoveryKey.publicKeyHash);
        if (!$.recoveryKeyHashes.contains(keyHash))
            revert RecoveryKeyNotFound();

        bytes32 digest = Codec.upgradeRecoveryDigest(
            address(this),
            block.chainid,
            newImplementation,
            $.pqOwner.publicSeed,
            $.pqOwner.publicKeyHash,
            recoveryKey.publicSeed,
            recoveryKey.publicKeyHash
        );

        if (!WOTSPlus.verify(recoveryKey, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            revert InvalidSignature();

        // Delegatecall to vetted implementation (defense-in-depth).
        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(this.verifyUpgrade, (newImplementation, payload))
        );

        $.recoveryKeyHashes.remove(keyHash);

        super.upgradeToAndCall(newImplementation, payload[0:0]);

        emit RecoveryUpgrade(newImplementation, recoveryKey);
    }

    /// @inheritdoc IQuipWallet
    function migrate(bytes calldata payload) external {
        if (_upgradeGuard() == 0) revert NotUpgrading();
        (
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        ) = Codec.decodeInit(payload);
        _enforceNonZeroPqOwner(newPqOwner);

        Storage.Layout storage $ = Storage.layout();
        $.pqOwner = newPqOwner;

        uint256 clearLen = $.recoveryKeyHashes.length();
        for (uint256 i = 0; i < clearLen; ++i) {
            $.recoveryKeyHashes.remove($.recoveryKeyHashes.at(0));
        }
        _addRecoveryKeys(recoveryKeys);
        _verifyInitialState();

        emit WalletMigrated(newPqOwner);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         VIEWS                                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipWallet
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) public view {
        (
            WOTSPlus.WinternitzAddress calldata verifier,
            WOTSPlus.WinternitzElements calldata verifySig
        ) = Codec.decodeUpgradeVerification(data);

        bytes32 digest = Codec.verificationDigest(
            address(this),
            block.chainid,
            newImplementation,
            verifier.publicSeed,
            verifier.publicKeyHash
        );

        if (!WOTSPlus.verify(verifier, WOTSPlus.WinternitzMessage({ messageHash: digest }), verifySig))
            revert InvalidSignature();
    }

    /// @inheritdoc IQuipWallet
    function quipFactory() public view returns (address payable) {
        return Storage.layout().quipFactory;
    }

    /// @inheritdoc IQuipWallet
    function pqOwner()
        public
        view
        returns (bytes32 publicSeed, bytes32 publicKeyHash)
    {
        Storage.Layout storage $ = Storage.layout();
        return ($.pqOwner.publicSeed, $.pqOwner.publicKeyHash);
    }

    /// @inheritdoc IQuipWallet
    function getRecoveryKeyCount() public view returns (uint256) {
        return Storage.layout().recoveryKeyHashes.length();
    }

    /// @inheritdoc IQuipWallet
    function getRecoveryKeyHashAt(uint256 index) public view returns (bytes32) {
        return Storage.layout().recoveryKeyHashes.at(index);
    }

    /// @inheritdoc IQuipWallet
    function isRecoveryKey(bytes32 keyHash) public view returns (bool) {
        return Storage.layout().recoveryKeyHashes.contains(keyHash);
    }

    /// @inheritdoc IQuipWallet
    function getVerificationKeyCount() public view returns (uint256) {
        return Storage.layout().verificationKeyset.length();
    }

    /// @inheritdoc IQuipWallet
    function getVerificationKeyAt(
        uint256 index
    ) public view returns (WOTSPlus.WinternitzAddress memory) {
        return Storage.layout().verificationKeyset.at(index);
    }

    /// @inheritdoc IQuipWallet
    function isVerificationKey(
        WOTSPlus.WinternitzAddress calldata key
    ) public view returns (bool) {
        return Storage.layout().verificationKeyset.contains(key);
    }

    /// @notice ERC-1271 validation via a Winternitz key in `verificationKeyset`.
    /// @dev Stateless/view: does NOT consume the key. Callers must rotate used keys
    ///      out-of-band via `replaceVerificationKeyAt` to avoid WOTS+ key reuse.
    ///      Signature layout: [0:64) verifier, [64:2208) pqSig.
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view override returns (bytes4) {
        if (signature.length != 2208) return 0xffffffff;
        (
            WOTSPlus.WinternitzAddress calldata verifier,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeErc1271Signature(signature);

        Storage.Layout storage $ = Storage.layout();
        if (!$.verificationKeyset.contains(verifier)) return 0xffffffff;

        bytes32 digest = Codec.erc1271Digest(
            address(this),
            block.chainid,
            verifier.publicSeed,
            verifier.publicKeyHash,
            hash
        );
        if (!WOTSPlus.verify(verifier, WOTSPlus.WinternitzMessage({ messageHash: digest }), pqSig))
            return 0xffffffff;

        return 0x1626ba7e;
    }

    /// @inheritdoc IQuipWallet
    function version() public view returns (uint256) {
        address impl;
        assembly {
            impl := sload(_ERC1967_IMPLEMENTATION_SLOT)
        }
        return IQuipFactory(FACTORY).getVettedCodeIndex(impl.codehash);
    }

    /// @inheritdoc IQuipWallet
    function getExecuteFee() public view returns (uint256) {
        return IQuipFactory(Storage.layout().quipFactory).executeFee();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        INTERNALS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _enforceNonZeroPqOwner(
        WOTSPlus.WinternitzAddress calldata pqOwner
    ) internal pure {
        if (
            pqOwner.publicSeed == bytes32(0) ||
            pqOwner.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqOwner();
    }

    function _enforceDifferentPqOwner(
        WOTSPlus.WinternitzAddress calldata nextPqOwner
    ) internal view {
        Storage.Layout storage $ = Storage.layout();
        if (
            nextPqOwner.publicSeed == $.pqOwner.publicSeed &&
            nextPqOwner.publicKeyHash == $.pqOwner.publicKeyHash
        ) revert PqOwnerReuse();
    }

    /// @dev Validates and adds recovery keys to the set. Reverts if any key has zero fields,
    ///      is a duplicate, or if the set would exceed `MAX_KEYS`.
    function _addRecoveryKeys(
        WOTSPlus.WinternitzAddress[] calldata keys
    ) internal {
        if (keys.length == 0) revert EmptyRecoveryKeys();
        EnumerableSetLib.Bytes32Set storage hashes = Storage
            .layout()
            .recoveryKeyHashes;
        uint256 len = keys.length;
        for (uint256 i = 0; i < len; ++i) {
            if (
                keys[i].publicSeed == bytes32(0) ||
                keys[i].publicKeyHash == bytes32(0)
            ) {
                revert ZeroValuePqOwner();
            }
            bytes32 keyHash = EfficientHashLib.hash(keys[i].publicSeed, keys[i].publicKeyHash);
            if (!hashes.add(keyHash, MAX_KEYS)) revert DuplicateRecoveryKey();
        }
    }

    /// @dev Fixed-size overload used by initialize (codec returns WinternitzAddress[10]).
    function _addRecoveryKeys(
        WOTSPlus.WinternitzAddress[10] calldata keys
    ) internal {
        EnumerableSetLib.Bytes32Set storage hashes = Storage
            .layout()
            .recoveryKeyHashes;
        for (uint256 i = 0; i < MAX_KEYS; ++i) {
            if (
                keys[i].publicSeed == bytes32(0) ||
                keys[i].publicKeyHash == bytes32(0)
            ) {
                revert ZeroValuePqOwner();
            }
            bytes32 keyHash = EfficientHashLib.hash(keys[i].publicSeed, keys[i].publicKeyHash);
            if (!hashes.add(keyHash, MAX_KEYS)) revert DuplicateRecoveryKey();
        }
    }

    function _verifyInitialState() internal view {
        Storage.Layout storage $ = Storage.layout();
        if ($.quipFactory == address(0)) revert ZeroAddressFactory();
        if (
            $.pqOwner.publicSeed == bytes32(0) ||
            $.pqOwner.publicKeyHash == bytes32(0)
        ) revert ZeroValuePqOwner();
        if ($.recoveryKeyHashes.length() != MAX_KEYS) revert IncorrectRecoveryKeyAmount();
    }

    /// @dev Validates and adds verification keys to the keyset. Reverts on zero-field,
    ///      duplicate, or capacity-exceeded.
    function _addVerificationKeys(
        WOTSPlus.WinternitzAddress[] calldata keys
    ) internal {
        Keyset.WinternitzAddressSet storage set = Storage.layout().verificationKeyset;
        uint256 len = keys.length;
        for (uint256 i = 0; i < len; ++i) {
            if (
                keys[i].publicSeed == bytes32(0) ||
                keys[i].publicKeyHash == bytes32(0)
            ) revert ZeroValuePqOwner();
            if (!set.add(keys[i], MAX_KEYS)) revert DuplicateVerificationKey();
        }
    }

    /// @dev Rotates the post-quantum owner key and emits `PqOwnerRotated`.
    function _rotatePqOwner(WOTSPlus.WinternitzAddress calldata nextPqOwner) internal {
        Storage.Layout storage $ = Storage.layout();
        WOTSPlus.WinternitzAddress memory oldPqOwner = $.pqOwner;
        $.pqOwner = nextPqOwner;
        emit PqOwnerRotated(oldPqOwner, nextPqOwner);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        PRIVATES                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _upgradeGuard() internal view returns (uint256 v) {
        uint256 slot = _UPGRADE_GUARD_SLOT;
        assembly { v := tload(slot) }
    }
}
