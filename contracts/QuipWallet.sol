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
    /// ownershipKey at base+3 (seed) and base+4 (hash), keyset spacer structs at base+5..+7.
    /// Keyset element slots are derived dynamically by `EnumerableWinternitzAddressSet._rootSlot`
    /// and are NOT guarded — the disaster recovery key is the rescue path if any keyset is
    /// corrupted via delegatecall or storageStore, and the ownership key is the backstop that
    /// still allows a compromised wallet to be handed over to a clean principal.
    bytes32 private constant _PQ_FACTORY_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;
    bytes32 private constant _DISASTER_KEY_SEED_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf701;
    bytes32 private constant _DISASTER_KEY_HASH_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf702;
    bytes32 private constant _OWNERSHIP_KEY_SEED_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf703;
    bytes32 private constant _OWNERSHIP_KEY_HASH_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf704;

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
    ///   - `nextKey` is already known to the wallet — present in any keyset
    ///     (transaction / recovery / verification) or matching either single PQ
    ///     key (disasterRecoveryKey, ownershipKey).
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
        // Global uniqueness check: `_safeAddKey` would revert on a cross-keyset or
        // single-key collision, but ERC-4337 validation must report failure via
        // `validationData == 1` rather than revert. Catching the collision here
        // keeps the EntryPoint's nonce / refund accounting clean.
        if (_isKeyInUse(nextKey)) return 1;

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
    ///      Blocks direct writes to: owner, ERC-1967 impl, quipFactory, both
    ///      `disasterRecoveryKey` slots (publicSeed + publicKeyHash), and both
    ///      `ownershipKey` slots.
    ///
    ///      The three keysets' root/element/length slots are intentionally NOT guarded
    ///      here — guarding them required ~60 lines of repeated assembly and could never
    ///      protect the position-mapping slots anyway. If a bad delegate corrupts any
    ///      keyset, the wallet can still be rescued via `saveWallet` (disaster key) or
    ///      transferred to a clean principal via `transferOwnership` (ownership key);
    ///      both backstop keys live in guarded slots. Owner / impl / factory are still
    ///      guarded to keep those rescue paths reachable and the ERC-4337 validation
    ///      path intact.
    modifier storageStoreGuard(bytes32 storageSlot) override {
        /// @solidity memory-safe-assembly
        assembly {
            if or(
                or(
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
                ),
                or(
                    eq(storageSlot, _OWNERSHIP_KEY_SEED_SLOT),
                    eq(storageSlot, _OWNERSHIP_KEY_HASH_SLOT)
                )
            ) {
                revert(codesize(), 0x00)
            }
        }
        _;
    }

    /// @dev Extends Solady's guard with PQ-specific protected slots. Snapshots
    ///      owner, impl, factory, both disaster-recovery-key slots, and both
    ///      ownership-key slots — 7 slots total, checked pre and post. See
    ///      `storageStoreGuard` for the rationale on why keyset slots are excluded.
    modifier delegateExecuteGuard() override {
        bytes32[7] memory snapshot = _snapshotGuardedSlots();
        _;
        _assertGuardedSlotsUnchanged(snapshot);
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
            WOTSPlus.WinternitzAddress calldata ownershipKey,
            WOTSPlus.WinternitzAddress[5] calldata transactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        ) = Codec.decodeInit(payload);

        _initializeOwner(newOwner);
        Storage.layout().quipFactory = FACTORY;
        _installInitialKeys(
            disasterRecoveryKey,
            ownershipKey,
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
    /// @dev Migrate is invoked via `LibCall.delegateCallContract` rather than folded
    ///      into `super.upgradeToAndCall(newImpl, migrateCalldata)` because Solady's
    ///      `upgradeToAndCall` takes `bytes calldata` and reads the payload via
    ///      `calldatacopy`, while `abi.encodeCall(this.migrate, (migratorPayload))`
    ///      produces `bytes memory` with no implicit memory→calldata conversion on
    ///      a super call. The explicit LibCall resolves this.
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

        // `verifyUpgrade` is declared view on this implementation, but we are about to
        // execute the NEW implementation's bytecode in our storage context. Snapshot
        // the guarded slots pre-call and assert they're unchanged post-call so a rogue
        // or buggy vetted impl cannot smuggle SSTOREs to owner/impl/factory/disaster/
        // ownership slots through the verify path.
        bytes32[7] memory verifyGuard = _snapshotGuardedSlots();
        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(this.verifyUpgrade, (newImplementation, data))
        );
        _assertGuardedSlotsUnchanged(verifyGuard);

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

        _collectExecuteFee();

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
        _reinitializeAndTransferOwnership(payload, false);
    }

    /// @inheritdoc IQuipWallet
    function completeOwnershipHandover(
        bytes calldata payload
    ) public payable onlyOwner {
        _reinitializeAndTransferOwnership(payload, true);
    }

    /// @inheritdoc IQuipWallet
    /// @dev Rotates a recovery key and reseeds the transaction keyset in one atomic
    ///      step. The signed digest binds (recoveryKey, newRecoveryKey, newTransactionKey)
    ///      so the WOTS+ signature commits to *both* the replacement recovery key and
    ///      the seed transaction key — neither is malleable post-sign.
    ///
    ///      Side effects:
    ///        - `recoveryKey` is burned; `newRecoveryKey` is installed in its place
    ///          via `_rotateKeys` (size-preserving — recovery capacity is conserved).
    ///        - The transaction keyset is fully cleared and reseeded with the single
    ///          `newTransactionKey`. Any in-flight transaction keys that may have been
    ///          observed/leaked are revoked.
    function recoverWallet(bytes calldata payload) public onlyOwner {
        (
            WOTSPlus.WinternitzAddress calldata recoveryKey,
            WOTSPlus.WinternitzAddress calldata newRecoveryKey,
            WOTSPlus.WinternitzAddress calldata newTransactionKey,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeRecoverWallet(payload);

        Storage.Layout storage $ = Storage.layout();
        // Cheapest-first fail-fast pre-checks before WOTS+ verify (~500k gas).
        // The two `_enforceDifferentKeys` calls reject self-rotation and the
        // newRecoveryKey/newTransactionKey collision (which would otherwise
        // surface only at the trailing `_safeAddKey($.transactionKeys, ...)`
        // long after WOTS+ verify and the recovery rotation have run).
        _enforceDifferentKeys(recoveryKey, newRecoveryKey);
        _enforceDifferentKeys(newRecoveryKey, newTransactionKey);
        _enforceContained($.recoveryKeys, recoveryKey);
        _enforceUnusedKey(newRecoveryKey);
        _enforceUnusedKey(newTransactionKey);

        bytes32 digest = Codec.recoverWalletDigest(
            address(this),
            block.chainid,
            recoveryKey.publicSeed,
            recoveryKey.publicKeyHash,
            newRecoveryKey.publicSeed,
            newRecoveryKey.publicKeyHash,
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

        _rotateKeys($.recoveryKeys, recoveryKey, newRecoveryKey);

        _clearKeys($.transactionKeys);
        _safeAddKey($.transactionKeys, newTransactionKey);

        emit PqRecovery(recoveryKey, newRecoveryKey, newTransactionKey);
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
        _enforceDifferentKeys(currentDisasterKey, newDisasterKey);
        if (
            newDisasterKey.publicSeed == bytes32(0) ||
            newDisasterKey.publicKeyHash == bytes32(0)
        ) revert UnknownDisasterRecoveryKey();
        _enforceUnusedKey(newDisasterKey);

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
            _safeAddKey($.transactionKeys, newTransactionKeys[i]);
        }
        for (uint256 i = 0; i < MAX_KEYS; ++i) {
            _safeAddKey($.recoveryKeys, newRecoveryKeys[i]);
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
    function replaceKeyAt(bytes calldata payload) public onlyOwner {
        (
            Codec.KeyType kind,
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            uint256 index,
            WOTSPlus.WinternitzAddress calldata newKey
        ) = Codec.decodeReplaceKeyAt(payload);

        Storage.Layout storage $ = Storage.layout();
        Keyset.WinternitzAddressSet storage target = _keyset(kind);

        // Snapshot `oldKey` before the auth rotation so the position reference is
        // stable. `at` reverts with `Keyset.IndexOutOfBounds` if `index` is out of
        // range, so no separate bounds check is needed here.
        WOTSPlus.WinternitzAddress memory oldKey = target.at(index);

        // Pre-verify guards. Catch malformed payloads before paying for digest
        // hashing and WOTS+ verification.
        //
        // 1. `oldKey == currentKey` (Transaction only): the auth rotation
        //    consumes `currentKey`, so trying to also replace it at its own
        //    slot would double-remove. Standalone rotation is achievable via
        //    any other transaction-key-bearing operation.
        if (
            kind == Codec.KeyType.Transaction &&
            oldKey.publicSeed == currentKey.publicSeed &&
            oldKey.publicKeyHash == currentKey.publicKeyHash
        ) revert ReplaceAuthKeyForbidden();
        // 2. `newKey == currentKey` (Transaction only): prevent double use of WOTS
        if (
            kind == Codec.KeyType.Transaction &&
            newKey.publicSeed == currentKey.publicSeed &&
            newKey.publicKeyHash == currentKey.publicKeyHash
        ) revert ReinstallSpentKeyForbidden();
        // 3. `newKey == oldKey` (any kind): a remove-then-add of the same key
        //    is a no-op shaped operation, almost certainly a payload-builder
        //    bug. `_enforceDifferentKeys` reverts `SameKey`.
        _enforceDifferentKeys(oldKey, newKey);

        bytes32 digest = Codec.replaceKeyAtDigest(
            kind,
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

        // Indexed replacement on `target`. Goes through `_rotateKeys` (which
        // wraps the safe remove + safe add primitives) so a library-level
        // bool=false on either op reverts loudly via `KeyRemovalFailed` /
        // `KeyAdditionFailed`. The size-neutral remove-then-add preserves the
        // MAX_KEYS cap.
        _rotateKeys(target, oldKey, newKey);

        emit KeyReplaced(kind, index, oldKey, newKey, nextKey);
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
            WOTSPlus.WinternitzAddress calldata currentRecoveryKey,
            WOTSPlus.WinternitzAddress calldata newRecoveryKey,
            WOTSPlus.WinternitzElements calldata pqSig
        ) = Codec.decodeRecoveryUpgradeAuth(payload);

        bytes32 digest = Codec.upgradeRecoveryDigest(
            address(this),
            block.chainid,
            newImplementation,
            currentRecoveryKey.publicSeed,
            currentRecoveryKey.publicKeyHash,
            newRecoveryKey.publicSeed,
            newRecoveryKey.publicKeyHash
        );

        // Enforce + verify + rotate the recovery key in place. Remove-then-add keeps
        // the recovery-key count stable at MAX_KEYS so a recoveryUpgrade does not
        // erode the defense-in-depth pool.
        _verifyAndRotate(
            Storage.layout().recoveryKeys,
            currentRecoveryKey,
            newRecoveryKey,
            pqSig,
            digest
        );

        // Delegatecall to vetted implementation (defense-in-depth). Guarded: snapshot
        // the 7 PQ-sensitive slots pre-call and assert they're unchanged post-call so
        // a rogue or buggy vetted impl cannot smuggle SSTOREs through the verify path.
        bytes32[7] memory verifyGuard = _snapshotGuardedSlots();
        LibCall.delegateCallContract(
            newImplementation,
            abi.encodeCall(
                this.verifyRecoveryUpgrade,
                (newImplementation, payload)
            )
        );
        _assertGuardedSlotsUnchanged(verifyGuard);

        super.upgradeToAndCall(newImplementation, payload[0:0]);

        emit RecoveryUpgrade(newImplementation, currentRecoveryKey);
    }

    /// @inheritdoc IQuipWallet
    function migrate(bytes calldata payload) external {
        if (_upgradeGuard() == 0) revert NotUpgrading();
        (
            WOTSPlus.WinternitzAddress calldata disasterRecoveryKey,
            WOTSPlus.WinternitzAddress calldata ownershipKey,
            WOTSPlus.WinternitzAddress[5] calldata transactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        ) = Codec.decodeInit(payload);

        Storage.Layout storage $ = Storage.layout();
        _clearKeys($.transactionKeys);
        _clearKeys($.recoveryKeys);
        _installInitialKeys(
            disasterRecoveryKey,
            ownershipKey,
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
    ///      used verification keys out-of-band via `replaceKeyAt` to
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

    /// @dev Appends calldata-provided keys to `set`, capped at `MAX_KEYS`. Each add
    ///      goes through `_safeAddKey` so the global uniqueness pre-check catches
    ///      cross-keyset collisions (`KeyInUse`) and within-batch duplicates
    ///      (the second occurrence finds the first already in `set`).
    function _addKeys(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress[] calldata keys
    ) internal {
        uint256 len = keys.length;
        for (uint256 i = 0; i < len; ++i) {
            _safeAddKey(set, keys[i]);
        }
    }

    /// @dev Drains all entries from `set`. Each removal goes through `_safeRemoveKey`
    ///      so a library invariant violation surfaces as a revert rather than silently
    ///      leaving stale entries behind.
    function _clearKeys(Keyset.WinternitzAddressSet storage set) internal {
        uint256 n = set.length();
        for (uint256 i = 0; i < n; ++i) {
            WOTSPlus.WinternitzAddress memory existing = set.at(0);
            _safeRemoveKey(set, existing);
        }
    }

    /// @dev Removes `currentKey` and installs `nextKey` in `set`. Remove-then-add
    ///      preserves size so a rotation at full capacity cannot trip the `MAX_KEYS` cap.
    ///      Memory-typed parameters so callers can pass either calldata (auto-copied)
    ///      or memory keys (e.g. from `target.at(index)` in `replaceKeyAt`).
    function _rotateKeys(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey
    ) internal {
        _safeRemoveKey(set, currentKey);
        _safeAddKey(set, nextKey);
        emit KeyRotated(currentKey, nextKey);
    }

    /// @dev Fail-fast membership checks, WOTS+ signature verification, then rotation.
    ///      Reverts with `SameKey` / `UnknownKey` / `KeyInUse` / `InvalidSignature`
    ///      on failure. Checks are ordered cheapest-first so a malformed payload
    ///      bails before we pay storage / WOTS+ verify gas:
    ///        1. `_enforceDifferentKeys(currentKey, nextKey)` — pure equality.
    ///        2. `_enforceContained(set, currentKey)` — one storage read.
    ///        3. `_enforceUnusedKey(nextKey)` — multiple storage reads, also
    ///           catches cross-keyset / single-key collisions.
    ///        4. WOTS+ verify (~500k gas).
    ///      Used by every owner-path that consumes a one-time WOTS+ key from a
    ///      keyset — transaction keys for most ops, recovery keys for
    ///      `recoveryUpgrade`.
    function _verifyAndRotate(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress calldata currentKey,
        WOTSPlus.WinternitzAddress calldata nextKey,
        WOTSPlus.WinternitzElements calldata pqSig,
        bytes32 digest
    ) internal {
        _enforceDifferentKeys(currentKey, nextKey);
        _enforceContained(set, currentKey);
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

    /// @dev Returns true if `key` is already known to this wallet — either a member
    ///      of any keyset (transaction / recovery / verification) or matching either
    ///      single PQ key (`disasterRecoveryKey`, `ownershipKey`). Used by
    ///      `_enforceUnusedKey` and the ERC-4337 validation path, which must
    ///      report failure via `validationData == 1` rather than revert.
    ///
    ///      A zero-valued probe (`publicSeed == 0` or `publicKeyHash == 0`) returns
    ///      false: zero keys are intrinsically invalid and will be rejected by the
    ///      keyset library's `ZeroValueWinternitzAddress` check downstream. The
    ///      short-circuit avoids a false positive against an uninitialized
    ///      `disasterRecoveryKey` / `ownershipKey` slot (which holds zero by default
    ///      until `initialize` runs) — this only matters in tests since production
    ///      flows always populate the singles before any add path is reachable, but
    ///      the guard keeps the helper robust regardless of caller context.
    function _isKeyInUse(
        WOTSPlus.WinternitzAddress memory key
    ) internal view returns (bool) {
        if (key.publicSeed == bytes32(0) || key.publicKeyHash == bytes32(0))
            return false;
        Storage.Layout storage $ = Storage.layout();
        if ($.transactionKeys.contains(key)) return true;
        if ($.recoveryKeys.contains(key)) return true;
        if ($.verificationKeys.contains(key)) return true;
        if (
            $.disasterRecoveryKey.publicSeed == key.publicSeed &&
            $.disasterRecoveryKey.publicKeyHash == key.publicKeyHash
        ) return true;
        if (
            $.ownershipKey.publicSeed == key.publicSeed &&
            $.ownershipKey.publicKeyHash == key.publicKeyHash
        ) return true;
        return false;
    }

    /// @dev Reverts with `KeyInUse` if `key` is already known to this wallet in any
    ///      keyset or single-key slot. WOTS+ is one-time-use: the same public key
    ///      living in two slots means one revealed signature burns it for every
    ///      purpose, so installation is forbidden across the board.
    function _enforceUnusedKey(
        WOTSPlus.WinternitzAddress memory key
    ) internal view {
        if (_isKeyInUse(key)) revert KeyInUse();
    }

    /// @dev Reverts with `SameKey` if `a` and `b` are the same WOTS+ public key
    ///      (both fields equal). Called at the top of every rotation site before
    ///      WOTS+ verify so a "rotate to self" payload fails fast without burning
    ///      verify gas and without producing a misleading no-op-shaped state
    ///      transition that would still consume the one-time WOTS+ signing
    ///      capability. Also used for cross-input checks where two new keys in
    ///      the same call must be distinct (e.g. `recoverWallet`'s
    ///      `newRecoveryKey` vs `newTransactionKey`).
    function _enforceDifferentKeys(
        WOTSPlus.WinternitzAddress memory a,
        WOTSPlus.WinternitzAddress memory b
    ) internal pure {
        if (a.publicSeed == b.publicSeed && a.publicKeyHash == b.publicKeyHash)
            revert SameKey();
    }

    /// @dev Wraps `set.add(key, MAX_KEYS)` with a global uniqueness pre-check and a
    ///      hard revert on bool=false. The pre-check rejects any key already known
    ///      to the wallet (any keyset or single-key slot) with `KeyInUse`. Because
    ///      that pre-check subsumes the in-set duplicate case, a `false` return
    ///      from `set.add` here can only mean cap excess — surfaced as
    ///      `KeyAdditionFailed` since the call sites have already proven non-cap
    ///      preconditions (`_clearKeys`-then-add, `_safeRemoveKey` in `_rotateKeys`,
    ///      `at(index)` in `replaceKeyAt`). Silent under-rotation in a one-time-
    ///      signature scheme is catastrophic; revert loudly.
    function _safeAddKey(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress memory key
    ) internal {
        _enforceUnusedKey(key);
        if (!set.add(key, MAX_KEYS)) revert KeyAdditionFailed();
    }

    /// @dev Wraps `set.remove(key)` with a hard revert on bool=false. Used by rotation
    ///      primitives where the call site has already proven `key` is a member (via
    ///      `_enforceContained` or `at(index)`). A false return indicates a library/
    ///      storage invariant violation — reverting prevents emitting `KeyRotated`
    ///      over a no-op that would leave a spent WOTS+ key live in the active set.
    function _safeRemoveKey(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress memory key
    ) internal {
        if (!set.remove(key)) revert KeyRemovalFailed();
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

    /// @dev Collects the current execute fee from the wallet balance. Shared
    ///      prelude for the three ERC-4337 execution entry points. The fee is a
    ///      required term of execution - if the wallet cannot
    ///      cover it, `safeTransferETH` reverts with `ETHTransferFailed()` and
    ///      the whole execution phase rolls back.
    function _collectExecuteFee() internal {
        uint256 fee = getExecuteFee();
        if (fee > 0) {
            SafeTransferLib.safeTransferETH(Storage.layout().quipFactory, fee);
        }
    }

    /// @dev Shared worker for `transferOwnership` and `completeOwnershipHandover`. Both call
    ///      paths are full re-initializations of the wallet's PQ state on behalf of the new
    ///      owner: the existing `ownershipKey` authorizes a bundle of (newOwner, new
    ///      `ownershipKey`, new `disasterRecoveryKey`, new transactionKeys[5], new
    ///      recoveryKeys[10]); on success the existing ownership key rotates, the disaster
    ///      key is replaced, the transaction and recovery keysets are cleared and repopulated,
    ///      and the verification keyset is cleared (the new owner re-seeds it out-of-band).
    ///
    ///      `isHandover` selects the domain tag on the signed digest so a signature produced
    ///      for `transferOwnership` cannot be replayed against `completeOwnershipHandover`
    ///      and vice versa.
    function _reinitializeAndTransferOwnership(
        bytes calldata payload,
        bool isHandover
    ) internal {
        (
            WOTSPlus.WinternitzAddress calldata currentOwnershipKey,
            WOTSPlus.WinternitzAddress calldata newOwnershipKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            address newOwner,
            WOTSPlus.WinternitzAddress calldata newDisasterKey,
            WOTSPlus.WinternitzAddress[5] calldata newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata newRecoveryKeys
        ) = Codec.decodeOwnershipTransfer(payload);

        if (newOwner == address(0)) revert ZeroAddressOwner();

        Storage.Layout storage $ = Storage.layout();

        if (
            $.ownershipKey.publicSeed != currentOwnershipKey.publicSeed ||
            $.ownershipKey.publicKeyHash != currentOwnershipKey.publicKeyHash
        ) revert UnknownOwnershipKey();

        if (
            newOwnershipKey.publicSeed == bytes32(0) ||
            newOwnershipKey.publicKeyHash == bytes32(0)
        ) revert UnknownOwnershipKey();
        // Auth rotation must be to a fresh key, and the two new singles must
        // be distinct (otherwise the trailing single-key uniqueness checks
        // would still catch it but only after WOTS+ verify).
        _enforceDifferentKeys(currentOwnershipKey, newOwnershipKey);
        _enforceDifferentKeys(newOwnershipKey, newDisasterKey);

        if (
            newDisasterKey.publicSeed == bytes32(0) ||
            newDisasterKey.publicKeyHash == bytes32(0)
        ) revert UnknownDisasterRecoveryKey();

        bytes32 keysHash = EfficientHashLib.hash(
            abi.encode(newDisasterKey, newTransactionKeys, newRecoveryKeys)
        );
        bytes32 digest = isHandover
            ? Codec.completeOwnershipHandoverDigest(
                address(this),
                block.chainid,
                currentOwnershipKey.publicSeed,
                currentOwnershipKey.publicKeyHash,
                newOwnershipKey.publicSeed,
                newOwnershipKey.publicKeyHash,
                newOwner,
                keysHash
            )
            : Codec.transferOwnershipDigest(
                address(this),
                block.chainid,
                currentOwnershipKey.publicSeed,
                currentOwnershipKey.publicKeyHash,
                newOwnershipKey.publicSeed,
                newOwnershipKey.publicKeyHash,
                newOwner,
                keysHash
            );

        if (
            !WOTSPlus.verify(
                currentOwnershipKey,
                WOTSPlus.WinternitzMessage({messageHash: digest}),
                pqSig
            )
        ) revert InvalidSignature();

        // Rotate ownership key, replace disaster key, wipe keysets, reinstall fresh ones.
        // Each single-key assignment is preceded by `_enforceUnusedKey` so the new
        // value cannot collide with anything currently in storage. Order matters:
        // ownership is enforced + assigned first, then disaster is enforced against the
        // freshly-set ownership. The keyset loops then run through `_safeAddKey`, which
        // re-checks against the new singles. Note this newly forbids
        // `newDisasterKey == oldDisasterKey` (caught here at the disaster-uniqueness
        // step, since the old value is still in storage) — a deliberate tightening for
        // WOTS+ one-time-use hygiene.
        _enforceUnusedKey(newOwnershipKey);
        $.ownershipKey = newOwnershipKey;
        _enforceUnusedKey(newDisasterKey);
        $.disasterRecoveryKey = newDisasterKey;
        _clearKeys($.transactionKeys);
        _clearKeys($.recoveryKeys);
        _clearKeys($.verificationKeys);
        for (uint256 i = 0; i < Codec.TRANSACTION_KEY_INIT_AMOUNT; ++i) {
            _safeAddKey($.transactionKeys, newTransactionKeys[i]);
        }
        for (uint256 i = 0; i < MAX_KEYS; ++i) {
            _safeAddKey($.recoveryKeys, newRecoveryKeys[i]);
        }

        if (isHandover) Ownable.completeOwnershipHandover(newOwner);
        else Ownable.transferOwnership(newOwner);

        emit OwnershipReinitialized(
            currentOwnershipKey,
            newOwnershipKey,
            newOwner,
            newDisasterKey,
            EfficientHashLib.hash(abi.encode(newTransactionKeys)),
            EfficientHashLib.hash(abi.encode(newRecoveryKeys))
        );
    }

    /// @dev Loads the disaster recovery key, ownership key, and the initial transaction-
    ///      and recovery-key batches into storage, then asserts the post-state invariants.
    ///      Shared by `initialize` and `migrate`; the caller is responsible for
    ///      clearing any prior keyset state.
    function _installInitialKeys(
        WOTSPlus.WinternitzAddress calldata disasterRecoveryKey,
        WOTSPlus.WinternitzAddress calldata ownershipKey,
        WOTSPlus.WinternitzAddress[5] calldata transactionKeys,
        WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
    ) internal {
        Storage.Layout storage $ = Storage.layout();
        // Each single-key assignment is preceded by `_enforceUnusedKey` so the new
        // value cannot collide with anything currently in storage (relevant for the
        // `migrate` path, where the old singles + the still-populated verification
        // keyset are visible at this point). Order matters: disaster is enforced +
        // assigned first, then ownership is enforced against the freshly-set disaster.
        // The keyset loops then run through `_safeAddKey`, which re-checks against
        // both new singles.
        _enforceUnusedKey(disasterRecoveryKey);
        $.disasterRecoveryKey = disasterRecoveryKey;
        _enforceUnusedKey(ownershipKey);
        $.ownershipKey = ownershipKey;
        for (uint256 i = 0; i < Codec.TRANSACTION_KEY_INIT_AMOUNT; ++i) {
            _safeAddKey($.transactionKeys, transactionKeys[i]);
        }
        for (uint256 i = 0; i < MAX_KEYS; ++i) {
            _safeAddKey($.recoveryKeys, recoveryKeys[i]);
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
        if (
            $.ownershipKey.publicSeed == bytes32(0) ||
            $.ownershipKey.publicKeyHash == bytes32(0)
        ) revert UnknownOwnershipKey();
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

    /// @dev Snapshots the 7 slots protected by `storageStoreGuard` into memory so a
    ///      caller can later verify none were modified by an intervening delegatecall.
    ///      Shared by `delegateExecuteGuard` and the upgrade/recoveryUpgrade verify
    ///      delegatecalls. Protected slots: owner, ERC-1967 impl, quipFactory, both
    ///      `disasterRecoveryKey` slots, both `ownershipKey` slots.
    function _snapshotGuardedSlots()
        internal
        view
        returns (bytes32[7] memory snapshot)
    {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(snapshot, sload(_OWNER_SLOT))
            mstore(add(snapshot, 0x20), sload(_ERC1967_IMPLEMENTATION_SLOT))
            mstore(add(snapshot, 0x40), sload(_PQ_FACTORY_SLOT))
            mstore(add(snapshot, 0x60), sload(_DISASTER_KEY_SEED_SLOT))
            mstore(add(snapshot, 0x80), sload(_DISASTER_KEY_HASH_SLOT))
            mstore(add(snapshot, 0xa0), sload(_OWNERSHIP_KEY_SEED_SLOT))
            mstore(add(snapshot, 0xc0), sload(_OWNERSHIP_KEY_HASH_SLOT))
        }
    }

    /// @dev Reverts with empty data if any of the 7 guarded slots has changed since
    ///      `_snapshotGuardedSlots` was called. Plain-bytes revert matches the style
    ///      of Solady's parent guards; the caller context (delegatecall target) is
    ///      already known to the operator by construction.
    function _assertGuardedSlotsUnchanged(
        bytes32[7] memory snapshot
    ) internal view {
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
            if iszero(
                eq(
                    mload(add(snapshot, 0xa0)),
                    sload(_OWNERSHIP_KEY_SEED_SLOT)
                )
            ) {
                revert(codesize(), 0x00)
            }
            if iszero(
                eq(
                    mload(add(snapshot, 0xc0)),
                    sload(_OWNERSHIP_KEY_HASH_SLOT)
                )
            ) {
                revert(codesize(), 0x00)
            }
        }
    }
}
