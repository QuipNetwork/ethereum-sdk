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
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {ECDSA} from "solady-0.1.26/src/utils/ECDSA.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "./interfaces/IQuipWallet.sol";
import {IQuipFactory} from "./interfaces/IQuipFactory.sol";
import {WOTSPlusCodec as Codec} from "./WOTSPlusCodec.sol";
import {WOTSPlusStorage as Storage} from "./storage/WOTSPlusStorage.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "./libraries/EnumerableWinternitzAddressSet.sol";

/// @title QuipWallet
contract QuipWallet is IQuipWallet, ERC4337, Initializable {
    using Keyset for Keyset.WinternitzAddressSet;

    uint256 public constant MAX_KEYS = 10;
    address payable public immutable FACTORY;

    /// @dev uint256(keccak256("quip.wallet.upgrade.guard")) - 1
    /// Transient storage slot used to gate `migrate` to the `upgradeToAndCall` context.
    /// @notice REQUIRES EIP-1153 (transient storage opcodes TSTORE/TLOAD).
    uint256 private constant _UPGRADE_GUARD_SLOT =
        0x490d87f9a8524f6238d75626265800824e3fa88e60bc82c13f11bbd9042ed677;

    /// @dev PQ storage base slot (ERC-7201 namespace: quip.storage.wallet.wotsplus).
    /// Layout: quipFactory at base+0, disasterRecoveryKey at base+1 (seed) and base+2 (hash),
    /// keyset spacer structs at base+3..+5. Keyset element slots are derived dynamically by
    /// `EnumerableWinternitzAddressSet._rootSlot` and are NOT guarded — the disaster recovery
    /// key is the rescue path if any keyset is corrupted via delegatecall or storageStore.
    bytes32 private constant _PQ_FACTORY_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;
    bytes32 private constant _DISASTER_KEY_SEED_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf701;
    bytes32 private constant _DISASTER_KEY_HASH_SLOT =
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
    /// Decodes a (currentKey, nextKey, pqSig) triple from `userOp.signature` and verifies
    /// the signature against `currentKey`.
    ///
    /// Validation fails (returns 1) when:
    ///   - `nextKey` is zero (missing key material).
    ///   - `currentKey` is not a member of the active transactionKeys set.
    ///   - `nextKey` is already a member of the active transactionKeys set.
    ///   - The WOTS+ signature does not verify against `currentKey`.
    ///
    /// On success the key rotation is committed immediately via `_rotateKeys`.
    /// The EntryPoint's `handleOps` invokes validation and execution as two separate
    /// top-level calls on the account within the same transaction. Writing the rotation
    /// during validation ensures the key is rotated regardless of whether the execution
    /// phase succeeds or fails.
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
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeUserOpSignature(userOp.signature);

        if (
            nextKey.publicSeed == bytes32(0) ||
            nextKey.publicKeyHash == bytes32(0)
        ) return 1;

        Storage.Layout storage $ = Storage.layout();
        if (!$.transactionKeys.contains(currentKey)) return 1;
        if ($.transactionKeys.contains(nextKey)) return 1;

        bytes32 digest = Codec.erc4337ExecuteDigest(
            address(this),
            block.chainid,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            userOpHash,
            getExecuteFee()
        );

        if (
            !WOTSPlus.verify(
                currentKey,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                pqSig
            )
        ) return 1;

        _rotateKeys($.transactionKeys, currentKey, nextKey);

        return 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   ERC-4337 EXECUTION                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc ERC4337
    /// @dev Key rotation is committed during `_validateSignature`.
    /// Owner must use `execute(bytes)` which has inline PQ auth.
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) public payable override onlyEntryPoint returns (bytes memory result) {
        _collectExecuteFee();
        result = super.execute(target, value, data);
    }

    /// @inheritdoc ERC4337
    /// @dev Key rotation is committed during `_validateSignature`.
    function executeBatch(
        Call[] calldata calls
    ) public payable override onlyEntryPoint returns (bytes[] memory results) {
        _collectExecuteFee();
        results = super.executeBatch(calls);
    }

    /// @inheritdoc ERC4337
    /// @dev Key rotation is committed during `_validateSignature`.
    function delegateExecute(
        address delegate,
        bytes calldata data
    )
        public
        payable
        override
        onlyEntryPoint
        delegateExecuteGuard
        returns (bytes memory result)
    {
        _collectExecuteFee();
        result = super.delegateExecute(delegate, data);
    }

    /// @inheritdoc ERC4337
    /// @dev Key rotation is committed during `_validateSignature`.
    function storageStore(
        bytes32 storageSlot,
        bytes32 storageValue
    ) public payable override onlyEntryPoint storageStoreGuard(storageSlot) {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(storageSlot, storageValue)
        }
    }

    /// @dev Extends Solady's guard with PQ-specific protected slots.
    ///      Blocks direct writes to: owner, ERC-1967 impl, quipFactory, and the two
    ///      slots of the `disasterRecoveryKey` (publicSeed + publicKeyHash).
    ///
    ///      The three keysets' root/element/length slots are intentionally NOT guarded
    ///      here — guarding them required ~60 lines of repeated assembly and could never
    ///      protect the position-mapping slots anyway. If a bad delegate corrupts any
    ///      keyset, the wallet can still be rescued via `saveWallet`, which is auth'd by
    ///      `disasterRecoveryKey` (whose storage slots ARE guarded). Owner / impl /
    ///      factory are still guarded to keep `saveWallet` reachable and the ERC-4337
    ///      validation path intact.
    modifier storageStoreGuard(bytes32 storageSlot) override {
        /// @solidity memory-safe-assembly
        assembly {
            if or(
                or(
                    or(
                        eq(storageSlot, _OWNER_SLOT),
                        eq(storageSlot, _ERC1967_IMPLEMENTATION_SLOT)
                    ),
                    eq(storageSlot, _PQ_FACTORY_SLOT)
                ),
                or(
                    eq(storageSlot, _DISASTER_KEY_SEED_SLOT),
                    eq(storageSlot, _DISASTER_KEY_HASH_SLOT)
                )
            ) {
                revert(codesize(), 0x00)
            }
        }
        _;
    }

    /// @dev Extends Solady's guard with PQ-specific protected slots. Snapshots
    ///      owner, impl, factory, and both disaster-recovery-key slots — 5 slots
    ///      total, checked pre and post. See `storageStoreGuard` for the rationale
    ///      on why keyset slots are excluded.
    modifier delegateExecuteGuard() override {
        bytes32[5] memory snapshot;
        /// @solidity memory-safe-assembly
        assembly {
            mstore(snapshot, sload(_OWNER_SLOT))
            mstore(add(snapshot, 0x20), sload(_ERC1967_IMPLEMENTATION_SLOT))
            mstore(add(snapshot, 0x40), sload(_PQ_FACTORY_SLOT))
            mstore(add(snapshot, 0x60), sload(_DISASTER_KEY_SEED_SLOT))
            mstore(add(snapshot, 0x80), sload(_DISASTER_KEY_HASH_SLOT))
        }
        _;
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(eq(mload(snapshot), sload(_OWNER_SLOT))) {
                revert(codesize(), 0x00)
            }
            if iszero(
                eq(
                    mload(add(snapshot, 0x20)),
                    sload(_ERC1967_IMPLEMENTATION_SLOT)
                )
            ) {
                revert(codesize(), 0x00)
            }
            if iszero(eq(mload(add(snapshot, 0x40)), sload(_PQ_FACTORY_SLOT))) {
                revert(codesize(), 0x00)
            }
            if iszero(
                eq(
                    mload(add(snapshot, 0x60)),
                    sload(_DISASTER_KEY_SEED_SLOT)
                )
            ) {
                revert(codesize(), 0x00)
            }
            if iszero(
                eq(
                    mload(add(snapshot, 0x80)),
                    sload(_DISASTER_KEY_HASH_SLOT)
                )
            ) {
                revert(codesize(), 0x00)
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          PUBLIC                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IQuipWallet
    function renounceOwnership()
        public
        payable
        override(IQuipWallet, Ownable)
        onlyOwner
    {
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
            WOTSPlus.WinternitzAddress calldata disasterRecoveryKey,
            WOTSPlus.WinternitzAddress[5] calldata transactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        ) = Codec.decodeInit(payload);

        _initializeOwner(newOwner);
        Storage.layout().quipFactory = FACTORY;
        _installInitialKeys(
            disasterRecoveryKey,
            transactionKeys,
            recoveryKeys
        );

        emit WalletInitialized(
            FACTORY,
            newOwner,
            transactionKeys,
            recoveryKeys
        );
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

        (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeUpgradeAuth(data);

        bytes32 digest = Codec.upgradeDigest(
            address(this),
            block.chainid,
            newImplementation,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash
        );

        Storage.Layout storage $ = Storage.layout();
        _verifyAndRotate(
            $.transactionKeys,
            currentKey,
            nextKey,
            pqSig,
            digest
        );

        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(this.verifyUpgrade, (newImplementation, data))
        );

        (bool shouldMigrate, bytes calldata migratorPayload) = Codec
            .decodeUpgradeMigration(data);
        if (shouldMigrate) {
            uint256 slot = _UPGRADE_GUARD_SLOT;
            assembly {
                tstore(slot, 1)
            }
            // abi.encodeCall re-serializes migratorPayload into fresh calldata,
            // so migrate's decodeInit reads from offset 0 of the init layout
            // regardless of where the slice sat in the original upgrade payload.
            LibCall.delegateCallContract(
                newImplementation,
                abi.encodeCall(this.migrate, (migratorPayload))
            );
            assembly {
                tstore(slot, 0)
            }
        }

        super.upgradeToAndCall(newImplementation, data[0:0]);
    }

    /// @inheritdoc IQuipWallet
    function changeTransactionKey(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeChangeTransactionKey(payload);

        bytes32 digest = Codec.keyRotationDigest(
            address(this),
            block.chainid,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash
        );

        _verifyAndRotate(
            Storage.layout().transactionKeys,
            currentKey,
            nextKey,
            pqSig,
            digest
        );
    }

    /// @inheritdoc IQuipWallet
    function execute(
        bytes calldata payload
    ) public payable onlyOwner returns (bytes memory) {
        (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            address target,
            uint256 value,
            bytes calldata data
        ) = Codec.decodeExecute(payload);

        uint256 fee = getExecuteFee();
        if (address(this).balance < value + fee)
            revert InsufficientBalance(value + fee, address(this).balance);

        bytes32 dataHash = EfficientHashLib.hashCalldata(data);
        bytes32 digest = Codec.executeDigest(
            address(this),
            block.chainid,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            target,
            value,
            dataHash,
            fee
        );

        Storage.Layout storage $ = Storage.layout();
        _verifyAndRotate(
            $.transactionKeys,
            currentKey,
            nextKey,
            pqSig,
            digest
        );

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
    function withdrawDepositTo(
        bytes calldata payload
    ) public payable onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            address to,
            uint256 amount
        ) = Codec.decodeWithdrawDeposit(payload);

        bytes32 digest = Codec.withdrawDepositDigest(
            address(this),
            block.chainid,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            to,
            amount
        );

        _verifyAndRotate(
            Storage.layout().transactionKeys,
            currentKey,
            nextKey,
            pqSig,
            digest
        );

        ERC4337.withdrawDepositTo(to, amount);
    }

    /// @inheritdoc IQuipWallet
    function transferOwnership(
        bytes calldata payload
    ) public payable onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            address newOwner
        ) = Codec.decodeOwnershipTransfer(payload);

        bytes32 digest = Codec.transferOwnershipDigest(
            address(this),
            block.chainid,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            newOwner
        );

        _verifyAndRotate(
            Storage.layout().transactionKeys,
            currentKey,
            nextKey,
            pqSig,
            digest
        );

        Ownable.transferOwnership(newOwner);
    }

    /// @inheritdoc IQuipWallet
    function completeOwnershipHandover(
        bytes calldata payload
    ) public payable onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            address pendingOwner
        ) = Codec.decodeOwnershipTransfer(payload);

        bytes32 digest = Codec.completeOwnershipHandoverDigest(
            address(this),
            block.chainid,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            pendingOwner
        );

        _verifyAndRotate(
            Storage.layout().transactionKeys,
            currentKey,
            nextKey,
            pqSig,
            digest
        );

        Ownable.completeOwnershipHandover(pendingOwner);
    }

    /// @inheritdoc IQuipWallet
    function recoverWallet(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata recoveryKey,
            WOTSPlus.WinternitzAddress calldata newTransactionKey,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeRecoverWallet(payload);

        Storage.Layout storage $ = Storage.layout();
        _enforceContained($.recoveryKeys, recoveryKey);
        _enforceUncontained($.transactionKeys, newTransactionKey);

        bytes32 digest = Codec.keyRotationDigest(
            address(this),
            block.chainid,
            recoveryKey.publicSeed,
            recoveryKey.publicKeyHash,
            newTransactionKey.publicSeed,
            newTransactionKey.publicKeyHash
        );

        if (
            !WOTSPlus.verify(
                recoveryKey,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                pqSig
            )
        ) revert InvalidSignature();

        $.recoveryKeys.remove(recoveryKey);

        _clearKeys($.transactionKeys);
        $.transactionKeys.add(newTransactionKey);

        emit PqRecovery(recoveryKey, newTransactionKey);
    }

    /// @inheritdoc IQuipWallet
    function saveWallet(bytes calldata payload) public {
        (
            WOTSPlus.WinternitzAddress calldata currentDisasterKey,
            WOTSPlus.WinternitzAddress calldata newDisasterKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[5] calldata newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata newRecoveryKeys
        ) = Codec.decodeSaveWallet(payload);

        Storage.Layout storage $ = Storage.layout();

        // The provided currentDisasterKey must match the stored one exactly.
        if (
            $.disasterRecoveryKey.publicSeed != currentDisasterKey.publicSeed ||
            $.disasterRecoveryKey.publicKeyHash !=
            currentDisasterKey.publicKeyHash
        ) revert UnknownDisasterRecoveryKey();

        // WOTS+ is one-time — the replacement must be distinct.
        if (
            newDisasterKey.publicSeed == currentDisasterKey.publicSeed &&
            newDisasterKey.publicKeyHash == currentDisasterKey.publicKeyHash
        ) revert DuplicateDisasterRecoveryKey();
        if (
            newDisasterKey.publicSeed == bytes32(0) ||
            newDisasterKey.publicKeyHash == bytes32(0)
        ) revert UnknownDisasterRecoveryKey();

        bytes32 keysHash = EfficientHashLib.hash(
            abi.encode(newTransactionKeys, newRecoveryKeys)
        );
        bytes32 digest = Codec.saveWalletDigest(
            address(this),
            block.chainid,
            currentDisasterKey.publicSeed,
            currentDisasterKey.publicKeyHash,
            newDisasterKey.publicSeed,
            newDisasterKey.publicKeyHash,
            keysHash
        );

        if (
            !WOTSPlus.verify(
                currentDisasterKey,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                pqSig
            )
        ) revert InvalidSignature();

        // Consume the disaster key first, then reset txn + recovery keysets.
        $.disasterRecoveryKey = newDisasterKey;
        _clearKeys($.transactionKeys);
        _clearKeys($.recoveryKeys);
        for (uint256 i = 0; i < Codec.TRANSACTION_KEY_INIT_AMOUNT; ++i) {
            if (!$.transactionKeys.add(newTransactionKeys[i], MAX_KEYS))
                revert DuplicateKey();
        }
        for (uint256 i = 0; i < MAX_KEYS; ++i) {
            if (!$.recoveryKeys.add(newRecoveryKeys[i], MAX_KEYS))
                revert DuplicateKey();
        }

        emit WalletSaved(
            currentDisasterKey,
            newDisasterKey,
            EfficientHashLib.hash(abi.encode(newTransactionKeys)),
            EfficientHashLib.hash(abi.encode(newRecoveryKeys))
        );
    }

    /// @inheritdoc IQuipWallet
    function addKeys(bytes calldata payload) public onlyOwner {
        _manageKeys(payload, false);
    }

    /// @inheritdoc IQuipWallet
    function refreshKeys(bytes calldata payload) public onlyOwner {
        _manageKeys(payload, true);
    }

    /// @inheritdoc IQuipWallet
    function replaceVerificationKeyAt(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            uint256 index,
            WOTSPlus.WinternitzAddress calldata newKey
        ) = Codec.decodeVerificationKeysReplace(payload);

        Storage.Layout storage $ = Storage.layout();

        if (index >= $.verificationKeys.length())
            revert VerificationKeyIndexOutOfBounds();

        WOTSPlus.WinternitzAddress memory oldKey = $.verificationKeys.at(index);

        bytes32 digest = Codec.verificationKeysReplaceDigest(
            address(this),
            block.chainid,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            index,
            newKey.publicSeed,
            newKey.publicKeyHash
        );

        _verifyAndRotate(
            $.transactionKeys,
            currentKey,
            nextKey,
            pqSig,
            digest
        );

        $.verificationKeys.remove(oldKey);
        // `add` enforces non-zero fields, and cap=MAX_KEYS is preserved since we just removed one.
        if (!$.verificationKeys.add(newKey, MAX_KEYS)) revert DuplicateKey();

        emit VerificationKeyReplaced(index, oldKey, newKey, nextKey);
    }

    /// @inheritdoc IQuipWallet
    function recoveryUpgrade(
        address newImplementation,
        bytes calldata payload
    ) public onlyOwner {
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
        ) = Codec.decodeRecoveryUpgradeAuth(payload);

        Storage.Layout storage $ = Storage.layout();

        _enforceContained($.recoveryKeys, recoveryKey);

        bytes32 digest = Codec.upgradeRecoveryDigest(
            address(this),
            block.chainid,
            newImplementation,
            recoveryKey.publicSeed,
            recoveryKey.publicKeyHash
        );

        if (
            !WOTSPlus.verify(
                recoveryKey,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                pqSig
            )
        ) revert InvalidSignature();

        // Delegatecall to vetted implementation (defense-in-depth).
        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(
                this.verifyRecoveryUpgrade,
                (newImplementation, payload)
            )
        );

        $.recoveryKeys.remove(recoveryKey);

        super.upgradeToAndCall(newImplementation, payload[0:0]);

        emit RecoveryUpgrade(newImplementation, recoveryKey);
    }

    /// @inheritdoc IQuipWallet
    function migrate(bytes calldata payload) external {
        if (_upgradeGuard() == 0) revert NotUpgrading();
        (
            WOTSPlus.WinternitzAddress calldata disasterRecoveryKey,
            WOTSPlus.WinternitzAddress[5] calldata transactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        ) = Codec.decodeInit(payload);

        Storage.Layout storage $ = Storage.layout();
        _clearKeys($.transactionKeys);
        _clearKeys($.recoveryKeys);
        _installInitialKeys(
            disasterRecoveryKey,
            transactionKeys,
            recoveryKeys
        );

        emit WalletMigrated(EfficientHashLib.hash(abi.encode(transactionKeys)));
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
        _verifyImplementationSig(newImplementation, verifier, verifySig);
    }

    /// @inheritdoc IQuipWallet
    function verifyRecoveryUpgrade(
        address newImplementation,
        bytes calldata data
    ) public view {
        (
            WOTSPlus.WinternitzAddress calldata verifier,
            WOTSPlus.WinternitzElements calldata verifySig
        ) = Codec.decodeRecoveryUpgradeVerification(data);
        _verifyImplementationSig(newImplementation, verifier, verifySig);
    }

    /// @inheritdoc IQuipWallet
    function quipFactory() public view returns (address payable) {
        return Storage.layout().quipFactory;
    }

    /// @inheritdoc IQuipWallet
    function keyCount(Codec.KeyType kind) public view returns (uint256) {
        return _keyset(kind).length();
    }

    /// @inheritdoc IQuipWallet
    function keyAt(
        Codec.KeyType kind,
        uint256 index
    ) public view returns (WOTSPlus.WinternitzAddress memory) {
        return _keyset(kind).at(index);
    }

    /// @inheritdoc IQuipWallet
    function isKey(
        Codec.KeyType kind,
        WOTSPlus.WinternitzAddress calldata key
    ) public view returns (bool) {
        return _keyset(kind).contains(key);
    }

    /// @notice ERC-1271 validation. Requires BOTH a valid WOTS+ signature from a
    ///         verification-keyset member AND a valid ECDSA signature from the
    ///         classical `owner()` over the raw `hash`.
    /// @dev Stateless/view: does NOT consume the WOTS+ key. Callers must rotate
    ///      used verification keys out-of-band via `replaceVerificationKeyAt` to
    ///      avoid WOTS+ key reuse.
    ///
    ///      AND semantics + raw-hash ECDSA is a failsafe: if the WOTS+ half ever
    ///      breaks (scheme bug, verifier flaw), the ECDSA half still binds the
    ///      hash to a signature from the wallet's classical owner. The ECDSA
    ///      check requires `owner()` to be an EOA so `ecrecover` can return a
    ///      meaningful address — contract owners do not currently satisfy this
    ///      path.
    ///
    ///      Signature layout: [0:64) verifier, [64:2208) pqSig, [2208:2273) ecdsaSig.
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view override returns (bytes4) {
        if (signature.length != 2273) return 0xffffffff;
        (
            WOTSPlus.WinternitzAddress calldata verifier,
            WOTSPlus.WinternitzElements calldata pqSig,
            bytes calldata ecdsaSig
        ) = Codec.decodeErc1271Signature(signature);

        address recovered = ECDSA.tryRecoverCalldata(hash, ecdsaSig);
        if (recovered == address(0) || recovered != owner())
            return 0xffffffff;

        Storage.Layout storage $ = Storage.layout();
        if (!$.verificationKeys.contains(verifier)) return 0xffffffff;

        bytes32 digest = Codec.erc1271Digest(
            address(this),
            block.chainid,
            verifier.publicSeed,
            verifier.publicKeyHash,
            hash
        );
        if (
            !WOTSPlus.verify(
                verifier,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                pqSig
            )
        ) return 0xffffffff;

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

    /// @dev Appends calldata-provided keys to `set`, capped at `MAX_KEYS`.
    ///      Library `add` enforces non-zero fields and capacity; duplicates return
    ///      false and surface here as `DuplicateKey`.
    function _addKeys(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress[] calldata keys
    ) internal {
        uint256 len = keys.length;
        for (uint256 i = 0; i < len; ++i) {
            if (!set.add(keys[i], MAX_KEYS)) revert DuplicateKey();
        }
    }

    /// @dev Drains all entries from `set`.
    function _clearKeys(Keyset.WinternitzAddressSet storage set) internal {
        uint256 n = set.length();
        for (uint256 i = 0; i < n; ++i) {
            WOTSPlus.WinternitzAddress memory existing = set.at(0);
            set.remove(existing);
        }
    }

    /// @dev Removes `currentKey` and installs `nextKey` in `set`. Remove-then-add
    ///      preserves size so a rotation at full capacity cannot trip the `MAX_KEYS` cap.
    function _rotateKeys(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress calldata currentKey,
        WOTSPlus.WinternitzAddress calldata nextKey
    ) internal {
        set.remove(currentKey);
        set.add(nextKey);
        emit KeyRotated(currentKey, nextKey);
    }

    /// @dev Fail-fast membership checks, WOTS+ signature verification, then rotation.
    ///      Reverts with `UnknownKey` / `DuplicateKey` / `InvalidSignature` on failure.
    ///      The pre-verify enforce pair short-circuits before paying WOTS+ verify gas
    ///      on invalid inputs. Used by every owner-path that consumes a transaction key.
    function _verifyAndRotate(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress calldata currentKey,
        WOTSPlus.WinternitzAddress calldata nextKey,
        WOTSPlus.WinternitzElements calldata pqSig,
        bytes32 digest
    ) internal {
        _enforceContained(set, currentKey);
        _enforceUncontained(set, nextKey);
        if (
            !WOTSPlus.verify(
                currentKey,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                pqSig
            )
        ) revert InvalidSignature();
        _rotateKeys(set, currentKey, nextKey);
    }

    /// @dev Shared worker for `addKeys` (append) and `refreshKeys` (clear-then-replace).
    ///      Decodes the payload, enforces/verifies/rotates the transaction keyset, then
    ///      applies the side-effect on the target keyset selected by `kind`.
    ///      For `replace == true`, disallows `Codec.KeyType.Transaction` and clears the target
    ///      before appending — emits `KeysRefreshed`. Otherwise emits `KeysAdded`.
    function _manageKeys(bytes calldata payload, bool replace) internal {
        (
            Codec.KeyType kind,
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata newKeys
        ) = Codec.decodeKeyManagement(payload);

        if (replace && kind == Codec.KeyType.Transaction)
            revert RefreshTransactionForbidden();
        if (newKeys.length == 0) revert EmptyKeys();

        bytes32 keysHash = EfficientHashLib.hash(abi.encode(newKeys));
        bytes32 digest = Codec.keysetDigest(
            kind,
            address(this),
            block.chainid,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            keysHash
        );

        _verifyAndRotate(
            Storage.layout().transactionKeys,
            currentKey,
            nextKey,
            pqSig,
            digest
        );

        Keyset.WinternitzAddressSet storage target = _keyset(kind);
        if (replace) _clearKeys(target);
        _addKeys(target, newKeys);

        if (replace) emit KeysRefreshed(kind, nextKey);
        else emit KeysAdded(kind, nextKey, newKeys.length);
    }

    /// @dev Returns the target keyset for `kind`.
    function _keyset(
        Codec.KeyType kind
    ) internal view returns (Keyset.WinternitzAddressSet storage set) {
        Storage.Layout storage $ = Storage.layout();
        if (kind == Codec.KeyType.Transaction) return $.transactionKeys;
        if (kind == Codec.KeyType.Recovery) return $.recoveryKeys;
        return $.verificationKeys;
    }

    /// @dev Reverts with `UnknownKey` if `key` is not a member of `set`.
    function _enforceContained(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress calldata key
    ) internal view {
        if (!set.contains(key)) revert UnknownKey();
    }

    /// @dev Reverts with `DuplicateKey` if `key` is already a member of `set`.
    function _enforceUncontained(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress calldata key
    ) internal view {
        if (set.contains(key)) revert DuplicateKey();
    }

    /// @dev Verifies a WOTS+ signature over the verification digest for an upgrade.
    ///      Shared by `verifyUpgrade` (called via delegatecall from `upgradeToAndCall`)
    ///      and `verifyRecoveryUpgrade` (called via delegatecall from `recoveryUpgrade`).
    ///      The two public entry points differ only in which portion of their payload
    ///      they decode the verifier from; the verification logic is identical.
    function _verifyImplementationSig(
        address newImplementation,
        WOTSPlus.WinternitzAddress calldata verifier,
        WOTSPlus.WinternitzElements calldata verifySig
    ) internal view {
        bytes32 digest = Codec.verificationDigest(
            address(this),
            block.chainid,
            newImplementation,
            verifier.publicSeed,
            verifier.publicKeyHash
        );
        if (
            !WOTSPlus.verify(
                verifier,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                verifySig
            )
        ) revert InvalidSignature();
    }

    /// @dev Collects the current execute fee from the wallet balance, if affordable.
    ///      Shared prelude for the three ERC-4337 execution entry points. The fee
    ///      transfer is part of the execution phase, so if the inner call reverts
    ///      the whole phase rolls back including the fee — the EntryPoint still
    ///      charges gas from the wallet's prefund deposit regardless.
    function _collectExecuteFee() internal {
        uint256 fee = getExecuteFee();
        if (fee > 0 && address(this).balance >= fee) {
            SafeTransferLib.safeTransferETH(Storage.layout().quipFactory, fee);
        }
    }

    /// @dev Loads the disaster recovery key and the initial transaction- and
    ///      recovery-key batches into storage, then asserts the post-state invariants.
    ///      Shared by `initialize` and `migrate`; the caller is responsible for
    ///      clearing any prior keyset state.
    function _installInitialKeys(
        WOTSPlus.WinternitzAddress calldata disasterRecoveryKey,
        WOTSPlus.WinternitzAddress[5] calldata transactionKeys,
        WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
    ) internal {
        Storage.Layout storage $ = Storage.layout();
        $.disasterRecoveryKey = disasterRecoveryKey;
        for (uint256 i = 0; i < Codec.TRANSACTION_KEY_INIT_AMOUNT; ++i) {
            if (!$.transactionKeys.add(transactionKeys[i], MAX_KEYS))
                revert DuplicateKey();
        }
        for (uint256 i = 0; i < MAX_KEYS; ++i) {
            if (!$.recoveryKeys.add(recoveryKeys[i], MAX_KEYS))
                revert DuplicateKey();
        }
        _verifyInitialState();
    }

    function _verifyInitialState() internal view {
        Storage.Layout storage $ = Storage.layout();
        if ($.quipFactory == address(0)) revert ZeroAddressFactory();
        if (
            $.disasterRecoveryKey.publicSeed == bytes32(0) ||
            $.disasterRecoveryKey.publicKeyHash == bytes32(0)
        ) revert UnknownDisasterRecoveryKey();
        if ($.transactionKeys.length() != Codec.TRANSACTION_KEY_INIT_AMOUNT)
            revert IncorrectTransactionKeyAmount();
        if ($.recoveryKeys.length() != MAX_KEYS)
            revert IncorrectRecoveryKeyAmount();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        PRIVATES                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _upgradeGuard() internal view returns (uint256 v) {
        uint256 slot = _UPGRADE_GUARD_SLOT;
        assembly {
            v := tload(slot)
        }
    }
}
