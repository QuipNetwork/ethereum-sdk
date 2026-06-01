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
// prettier-ignore
import {
    EnumerableWinternitzAddressSet as Keyset
} from "./libraries/EnumerableWinternitzAddressSet.sol";

/// @title QuipWallet
contract QuipWallet is IQuipWallet, ERC4337, Initializable {
    using Keyset for Keyset.WinternitzAddressSet;

    /// @dev Per-keyset capacity bound. Distinct from `Codec.RECOVERY_KEY_AMOUNT`
    ///      (the protocol-required INITIAL recovery-set size, currently 10) and
    ///      `Codec.TRANSACTION_KEY_INIT_AMOUNT` (initial transaction-set size,
    ///      currently 5).
    uint256 public constant MAX_KEYS = 10;
    address payable public immutable FACTORY;

    /// @dev Transient storage slot used to gate `migrate` to the `upgradeToAndCall` context.
    /// @notice REQUIRES EIP-1153 (transient storage opcodes TSTORE/TLOAD).
    uint256 private constant _UPGRADE_GUARD_SLOT =
        uint256(keccak256("quip.wallet.upgrade.guard")) - 1;

    /// @dev PQ storage base slot (ERC-7201 namespace: quip.storage.wallet.wotsplus).
    /// Layout: quipFactory at base+0, disasterRecoveryKey at base+1 (seed) and base+2 (hash),
    /// ownershipKey at base+3 (seed) and base+4 (hash), keyset spacer structs at base+5..+7.
    /// Keyset element slots are derived dynamically by `EnumerableWinternitzAddressSet._rootSlot`
    /// and are NOT guarded — the disaster recovery key is the rescue path if any keyset is
    /// corrupted via delegatecall or storageStore, and the ownership key is the backstop that
    /// still allows a compromised wallet to be handed over to a clean principal.
    ///
    /// These literals are duplicated from `WOTSPlusStorage.sol` (where the
    /// canonical hex values are declared as `internal constant`) because
    /// Solidity's inline assembly only accepts direct numeric constants — it
    /// rejects cross-library references and expressions like `base + N`.
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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   INTERNAL OVERRIDES                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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
        ) {
            emit UserOpValidationRejected(UserOpValidationFailure.ZeroNextKey);
            return 1;
        }

        Storage.Layout storage $ = Storage.layout();
        if (!$.transactionKeys.contains(currentKey)) {
            emit UserOpValidationRejected(
                UserOpValidationFailure.StaleCurrentKey
            );
            return 1;
        }
        // Global uniqueness check: `_safeAddKey` would revert on  but ERC-4337 
        /// validation must report failure via `validationData == 1` rather than revert. 
        /// Catching the collision here keeps the EntryPoint's nonce / refund accounting 
        /// clean.
        if (_isKeySpent(nextKey)) {
            emit UserOpValidationRejected(
                UserOpValidationFailure.NextKeyAlreadyInUse
            );
            return 1;
        }

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
        ) {
            emit UserOpValidationRejected(
                UserOpValidationFailure.InvalidSignature
            );
            return 1;
        }

        _rotateKeys($.transactionKeys, currentKey, nextKey);

        return 0;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                ERC-4337 EXECUTION                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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
        bytes4 selector = GuardedSlotWriteDenied.selector;
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
                mstore(0x00, selector)
                revert(0x00, 0x04)
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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       PUBLIC                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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
    ///      All ownership transfers MUST go through the WOTS+-authenticated
    ///      `transferOwnership(bytes)`.
    function transferOwnership(address) public payable override {
        revert ClassicalTransferOwnershipDisabled();
    }

    /// @dev Disables Solady's two-step ownership handover. The wallet supports
    ///      only the WOTS+-authenticated `transferOwnership(bytes)` path, which
    ///      atomically rotates the PQ ownership key, re-seeds keysets, commits
    ///      Solady's `_setOwner(newOwner)`, and notifies the factory. The two-
    ///      step pattern's typo-mitigation value is subsumed by the WOTS+
    ///      signature already committing cryptographically to `newOwner`.
    function requestOwnershipHandover() public payable override {
        revert OwnershipHandoverDisabled();
    }

    /// @dev Disabled; see `requestOwnershipHandover`.
    function cancelOwnershipHandover() public payable override {
        revert OwnershipHandoverDisabled();
    }

    /// @dev Disabled; see `requestOwnershipHandover`. The handover-bytes path
    ///      that previously lived here has been removed entirely.
    function completeOwnershipHandover(address) public payable override {
        revert OwnershipHandoverDisabled();
    }

    /// @inheritdoc IQuipWallet
    /// @dev Trivial delegate to Solady's `Ownable.owner()`. Explicit override
    ///      is required because both `IQuipWallet` and `Ownable` declare it.
    function owner()
        public
        view
        override(IQuipWallet, Ownable)
        returns (address)
    {
        return Ownable.owner();
    }

    /// @dev Overridden to return 0 unconditionally. The two-step ownership
    ///      handover is disabled (see `requestOwnershipHandover`), so no
    ///      handover can ever be pending; returning 0 honestly reflects that
    ///      to any tooling that speculatively reads this view.
    function ownershipHandoverExpiresAt(
        address
    ) public pure override returns (uint256) {
        return 0;
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
        // SECURITY — Checks-Effects-Interactions (CEI). DO NOT BREAK CEI HERE.
        // This rotation IS the Effect that prevents signed-payload REPLAY
        // ATTACKS: `_verifyAndRotate` removes `currentKey` from
        // `transactionKeys`, so a re-entrant call (e.g., from a malicious
        // vetted impl during the delegatecall below) replaying the same
        // upgrade payload reverts with `UnknownKey`. Every delegatecall and
        // `super.upgradeToAndCall` below is an Interaction. Reordering any of
        // them before this rotation re-opens the replay surface.
        _verifyAndRotate($.transactionKeys, currentKey, nextKey, pqSig, digest);

        // `verifyUpgrade` is declared view on this implementation, but we are about to
        // execute the NEW implementation's bytecode in our storage context. Snapshot
        // the guarded slots pre-call and assert they're unchanged post-call so a rogue
        // or buggy vetted impl cannot smuggle SSTOREs to owner/impl/factory/disaster/
        // ownership slots through the verify path.
        // SECURITY (CEI): Interactions below MUST remain after
        // `_verifyAndRotate` above to preserve replay-attack protection.
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
        // SECURITY — Checks-Effects-Interactions (CEI). DO NOT BREAK CEI HERE.
        // This rotation IS the Effect that prevents signed-payload REPLAY
        // ATTACKS: `_verifyAndRotate` removes `currentKey` from
        // `transactionKeys`, so if a callee below re-enters `execute(bytes)`
        // with the same signed payload, the next `_verifyAndRotate` reverts
        // with `UnknownKey` because `currentKey` is no longer in the keyset.
        // Every line below this point is an Interaction (fee transfer to
        // factory, user-directed external call to `target`). A future refactor
        // that moves any Interaction before this rotation — or moves the
        // rotation after an Interaction — breaks CEI and re-opens the replay
        // surface, allowing an attacker to drain the wallet by re-executing
        // the same signed payload through a malicious target.
        _verifyAndRotate($.transactionKeys, currentKey, nextKey, pqSig, digest);

        // SECURITY (CEI): Interaction. MUST remain after `_verifyAndRotate`
        // above to preserve replay-attack protection.
        _collectExecuteFee();

        // Empty execute (value == 0 && data.length == 0): the signature was
        // valid and the key already rotated in `_verifyAndRotate`, so the only
        // remaining work is paying the fee (already done) and surfacing a
        // distinct event so an indexer / wallet UI can tell this apart from a
        // real transfer to `target` with zero value.
        if (value == 0 && data.length == 0) {
            emit KeyRotationOnly(currentKey, nextKey);
            return "";
        }

        bytes memory result;
        if (data.length == 0) {
            // SECURITY (CEI): Interaction. MUST remain after `_verifyAndRotate`
            // above to preserve replay-attack protection.
            SafeTransferLib.safeTransferETH(target, value);
        } else {
            // SECURITY (CEI): Interaction. MUST remain after `_verifyAndRotate`
            // above to preserve replay-attack protection.
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

        // SECURITY — Checks-Effects-Interactions (CEI). DO NOT BREAK CEI HERE.
        // This rotation IS the Effect that prevents signed-payload REPLAY
        // ATTACKS: `_verifyAndRotate` removes `currentKey` from
        // `transactionKeys`, so a re-entrant call replaying the same withdraw
        // payload reverts with `UnknownKey`. The `ERC4337.withdrawDepositTo`
        // call below is an Interaction (sends ETH from the EntryPoint deposit
        // to `to`); reordering it before this rotation re-opens the replay
        // surface and allows draining the deposit by re-execution.
        _verifyAndRotate(
            Storage.layout().transactionKeys,
            currentKey,
            nextKey,
            pqSig,
            digest
        );

        // SECURITY (CEI): Interaction. MUST remain after `_verifyAndRotate`
        // above to preserve replay-attack protection.
        ERC4337.withdrawDepositTo(to, amount);
    }

    /// @inheritdoc IQuipWallet
    function transferOwnership(
        bytes calldata payload
    ) public payable onlyOwner {
        _reinitializeAndTransferOwnership(payload);
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
        _enforceUnspentKey(newDisasterKey);

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
        _setDisasterRecoveryKey(newDisasterKey);
        _clearKeys($.transactionKeys);
        _clearKeys($.recoveryKeys);
        for (uint256 i = 0; i < Codec.TRANSACTION_KEY_INIT_AMOUNT; ++i) {
            _safeAddKey($.transactionKeys, newTransactionKeys[i]);
        }
        for (uint256 i = 0; i < Codec.RECOVERY_KEY_AMOUNT; ++i) {
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
    /// @dev N-for-N swap on target keyset `kind`, authorized by one WOTS+
    ///      signature from `signingKind` (tx or recovery). Codec asserts
    ///      payload structural integrity: `payload.length == 2368 + 2*n*64`
    ///      and `oldKeys.length == newKeys.length == n`. The function
    ///      re-asserts the array lengths as belt-and-suspenders. 
    ///      *********************************************************
    ///      IF CODEC IS EDITED, THEN TRAILING BYTES MAY BE ADDED TO THE
    ///      PAYLOAD
    ///      *********************************************************
    function replaceKeys(bytes calldata payload) public onlyOwner {
        (
            Codec.KeyType kind,
            Codec.KeyType signingKind,
            uint256 n,
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata oldKeys,
            WOTSPlus.WinternitzAddress[] calldata newKeys
        ) = Codec.decodeReplaceKeys(payload);

        // Re-assertion so future codec refactor that drops 
        // the check fails loudly here.
        if (oldKeys.length != n || newKeys.length != n)
            revert MalformedPayload();

        if (signingKind == Codec.KeyType.Verification)
            revert InvalidSigningKeyset();
        if (n == 0) revert EmptyKeys();

        // SECURITY — CEI. The signing rotation IS the Effect that prevents
        // signed-payload replay: `_verifyAndRotate` removes `currentKey`
        // from the signing set, so a re-entrant call replaying this payload
        // reverts with `UnknownKey`. The target-set loop below is purely
        // internal — no external interactions on this path — but ordering
        // still matters if a future refactor introduces one.
        // The `_enforceContained` inside `_verifyAndRotate` doubles as the
        // "claimed signingKind matches reality" integrity check.
        // Digest computation is delegated to a helper to keep this frame's
        // stack within the Solidity stack-too-deep budget.
        _verifyAndRotate(
            _keyset(signingKind),
            currentKey,
            nextKey,
            pqSig,
            _replaceKeysDigest(
                kind,
                signingKind,
                n,
                currentKey,
                nextKey,
                oldKeys,
                newKeys
            )
        );

        Keyset.WinternitzAddressSet storage target = _keyset(kind);

        // DRIFT: cross-array overlap (oldKeys[i] == newKeys[j]) is caught by
        // `_safeAddKey`'s `_enforceUnspentKey` (the original install
        // `_markKeySpent`'d `oldKeys[i]`, so the same value cannot be
        // re-added); missing-old-key is caught by `_safeRemoveKey`'s false-
        // return revert. Weakening either helper regresses those checks
        // silently.
        // Order is remove-then-add — reversing trips `_safeAddKey`'s
        // MAX_KEYS cap (target sits at capacity by invariant).
        for (uint256 i = 0; i < n; ++i) {
            _safeRemoveKey(target, oldKeys[i]);
            _safeAddKey(target, newKeys[i]);
        }

        emit KeysReplaced(
            kind,
            signingKind,
            currentKey,
            nextKey,
            oldKeys,
            newKeys
        );
    }

    /// @inheritdoc IQuipWallet
    /// @dev Wholesale reset of target keyset `kind`, authorized by one WOTS+
    ///      signature from `signingKind` (tx or recovery). Sequence is:
    ///      verify+rotate signing keyset → clear target → install 10 new keys.
    ///      When `signingKind == kind`, the rotation transiently adds
    ///      `nextKey` to the target, which the subsequent `_clearKeys` wipes;
    ///      `_safeAddKey`'s burn-index guard then rejects any `newKeys[i]`
    ///      matching `currentKey` or `nextKey` with `KeyInUse`.
    ///      Codec asserts the fixed 2976-byte payload length, so no
    ///      wallet-level length re-assertion is needed.
    function resetKeyset(bytes calldata payload) public onlyOwner {
        (
            Codec.KeyType kind,
            Codec.KeyType signingKind,
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[10] calldata newKeys
        ) = Codec.decodeResetKeyset(payload);

        if (signingKind == Codec.KeyType.Verification)
            revert InvalidSigningKeyset();

        // SECURITY — CEI. The signing rotation IS the Effect that prevents
        // signed-payload replay: `_verifyAndRotate` removes `currentKey` from
        // the signing set, so a re-entrant call replaying this payload
        // reverts with `UnknownKey`. Target-set mutations below are purely
        // internal — no external interactions on this path — but ordering
        // still matters if a future refactor introduces one.
        _verifyAndRotate(
            _keyset(signingKind),
            currentKey,
            nextKey,
            pqSig,
            Codec.resetKeysetDigest(
                kind,
                signingKind,
                address(this),
                block.chainid,
                currentKey.publicSeed,
                currentKey.publicKeyHash,
                nextKey.publicSeed,
                nextKey.publicKeyHash,
                EfficientHashLib.hash(abi.encode(newKeys))
            )
        );

        Keyset.WinternitzAddressSet storage target = _keyset(kind);

        // Wipe the target in a single pass, then install the 10 fresh keys.
        // `_clearKeys` is a no-op on an empty set (verification keyset before
        // the always-10 invariant is established). The install loop calls
        // `_safeAddKey` which enforces the burn-index check — any historical
        // key, including `currentKey` and `nextKey` from the rotation above,
        // reverts `KeyInUse`.
        _clearKeys(target);
        for (uint256 i = 0; i < 10; ++i) {
            _safeAddKey(target, newKeys[i]);
        }

        emit KeysetReset(kind, signingKind, currentKey, nextKey, newKeys);
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
        // SECURITY — Checks-Effects-Interactions (CEI). DO NOT BREAK CEI HERE.
        // This rotation IS the Effect that prevents signed-payload REPLAY
        // ATTACKS: `_verifyAndRotate` removes `currentRecoveryKey` from
        // `recoveryKeys`, so a re-entrant call (e.g., from a malicious vetted
        // impl during the delegatecall below) replaying the same recovery
        // upgrade payload reverts with `UnknownKey`. Every delegatecall and
        // `super.upgradeToAndCall` below is an Interaction. Reordering any of
        // them before this rotation re-opens the replay surface.
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
        // SECURITY (CEI): Interactions below MUST remain after
        // `_verifyAndRotate` above to preserve replay-attack protection.
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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      VIEWS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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
    function getDisasterRecoveryKey()
        public
        view
        returns (WOTSPlus.WinternitzAddress memory)
    {
        return Storage.layout().disasterRecoveryKey;
    }

    /// @inheritdoc IQuipWallet
    function getOwnershipKey()
        public
        view
        returns (WOTSPlus.WinternitzAddress memory)
    {
        return Storage.layout().ownershipKey;
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

    /// @inheritdoc IQuipWallet
    function isKeySpent(
        WOTSPlus.WinternitzAddress calldata key
    ) public view returns (bool) {
        return _isKeySpent(key);
    }

    /// @inheritdoc IQuipWallet
    function getKeyset(
        Codec.KeyType kind
    ) public view returns (WOTSPlus.WinternitzAddress[] memory) {
        return _keyset(kind).values();
    }

    /// @inheritdoc IQuipWallet
    function getAllKeys() public view returns (AllKeys memory) {
        Storage.Layout storage $ = Storage.layout();
        return
            AllKeys({
                disasterRecoveryKey: $.disasterRecoveryKey,
                ownershipKey: $.ownershipKey,
                transactionKeys: $.transactionKeys.values(),
                recoveryKeys: $.recoveryKeys.values(),
                verificationKeys: $.verificationKeys.values()
            });
    }

    /// @notice ERC-1271 validation. Requires BOTH a valid WOTS+ signature from a
    ///         verification-keyset member AND a valid ECDSA signature from the
    ///         classical `owner()` over the raw `hash`.
    /// @dev EIP-1271 mandates `view`, so this function cannot burn the verifier
    ///      on-chain. Caller obligations:
    ///        - Rotate the verifier after each signature via
    ///          `replaceKeys(KeyType.Verification, ...)`. WOTS+ leaks chain
    ///          material on every signature, so multi-use erodes unforgeability —
    ///          a cryptographic requirement, not just integrator hygiene.
    ///        - Bake a nonce / deadline into the signed `hash`. The wallet
    ///          provides no anti-replay layer here; consumer protocols
    ///          (Permit2, Seaport, etc.) follow this convention.
    ///
    ///      AND-gated ECDSA is a failsafe against a WOTS+ scheme break, not
    ///      anti-replay. Requires `owner()` to be an EOA.
    ///
    ///      Signature layout: [0:64) verifier, [64:2208) pqSig, [2208:2273) ecdsaSig.
    ///      Failure branches collapse to the EIP-1271 magic; use
    ///      `debugIsValidSignature` via `eth_call` to discriminate.
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view override returns (bytes4) {
        return
            _checkErc1271Signature(hash, signature) ==
                Erc1271ValidationResult.Ok
                ? bytes4(0x1626ba7e)
                : bytes4(0xffffffff);
    }

    /// @inheritdoc IQuipWallet
    function debugIsValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (Erc1271ValidationResult) {
        return _checkErc1271Signature(hash, signature);
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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     INTERNALS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Shared core for `isValidSignature` and `debugIsValidSignature`.
    ///      Returns the first failing branch, or `Ok` if every check passes.
    ///      Order matches `isValidSignature`'s legacy short-circuit:
    ///      length → ECDSA → keyset membership → WOTS+ verify.
    function _checkErc1271Signature(
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (Erc1271ValidationResult) {
        if (signature.length != 2273) {
            return Erc1271ValidationResult.BadSignatureLength;
        }
        (
            WOTSPlus.WinternitzAddress calldata verifier,
            WOTSPlus.WinternitzElements calldata pqSig,
            bytes calldata ecdsaSig
        ) = Codec.decodeErc1271Signature(signature);

        address recovered = ECDSA.tryRecoverCalldata(hash, ecdsaSig);
        if (recovered == address(0) || recovered != owner()) {
            return Erc1271ValidationResult.InvalidEcdsaSignature;
        }

        Storage.Layout storage $ = Storage.layout();
        if (!$.verificationKeys.contains(verifier)) {
            return Erc1271ValidationResult.UnknownVerifier;
        }

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
        ) {
            return Erc1271ValidationResult.InvalidPqSignature;
        }

        return Erc1271ValidationResult.Ok;
    }

    /// @dev Drains all entries from `set` via the library's single-pass
    ///      `clear()` helper. Snapshots the prior length and asserts the
    ///      returned count matches so a library invariant violation still
    ///      surfaces as a revert rather than silently leaving stale entries
    ///      behind — preserving the safety net the previous per-element
    ///      `_safeRemoveKey` loop provided.
    function _clearKeys(Keyset.WinternitzAddressSet storage set) internal {
        uint256 expected = set.length();
        uint256 cleared = set.clear();
        if (cleared != expected) revert KeyRemovalFailed();
    }

    /// @dev Removes `currentKey` and installs `nextKey` in `set`. Remove-then-add
    ///      preserves size so a rotation at full capacity cannot trip the `MAX_KEYS` cap.
    ///      Memory-typed parameters so callers can pass either calldata
    ///      (auto-copied) or memory keys.
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
    ///        3. `_enforceUnspentKey(nextKey)` — multiple storage reads, also
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

    /// @dev Returns the target keyset for `kind`.
    function _keyset(
        Codec.KeyType kind
    ) internal view returns (Keyset.WinternitzAddressSet storage set) {
        Storage.Layout storage $ = Storage.layout();
        if (kind == Codec.KeyType.Transaction) return $.transactionKeys;
        if (kind == Codec.KeyType.Recovery) return $.recoveryKeys;
        return $.verificationKeys;
    }

    /// @dev Builds the `replaceKeys` digest. Extracted from `replaceKeys` so
    ///      its 11-arg signature does not consume the caller's stack frame
    ///      and trip Solidity's stack-too-deep budget.
    function _replaceKeysDigest(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        uint256 n,
        WOTSPlus.WinternitzAddress calldata currentKey,
        WOTSPlus.WinternitzAddress calldata nextKey,
        WOTSPlus.WinternitzAddress[] calldata oldKeys,
        WOTSPlus.WinternitzAddress[] calldata newKeys
    ) internal view returns (bytes32) {
        return
            Codec.replaceKeysDigest(
                kind,
                signingKind,
                n,
                address(this),
                block.chainid,
                currentKey.publicSeed,
                currentKey.publicKeyHash,
                nextKey.publicSeed,
                nextKey.publicKeyHash,
                EfficientHashLib.hash(abi.encode(oldKeys)),
                EfficientHashLib.hash(abi.encode(newKeys))
            );
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

    /// @dev Hashes a WOTS+ public key into the lookup value used by the
    ///      monotonic `isKeySpent` burn index. Mirrors `QuipPaymaster._verifierHash`
    ///      so wallet and paymaster lock semantics are constructed identically.
    function _keyHash(
        WOTSPlus.WinternitzAddress memory key
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(key.publicSeed, key.publicKeyHash);
    }

    /// @dev Returns true if `key` has EVER been installed in this wallet — in any
    ///      keyset (transaction / recovery / verification) or either single PQ slot
    ///      (`disasterRecoveryKey`, `ownershipKey`). The burn index is monotonic:
    ///      once a key has been seen on-chain, its WOTS+ chain material is assumed
    ///      revealed, so it can never be re-installed. Used by `_enforceUnspentKey`
    ///      and the ERC-4337 validation path, which must report failure via
    ///      `validationData == 1` rather than revert.
    ///
    ///      A zero-valued probe (`publicSeed == 0` or `publicKeyHash == 0`) returns
    ///      false: zero keys are intrinsically invalid and will be rejected by the
    ///      keyset library's `ZeroValueWinternitzAddress` check downstream. The
    ///      short-circuit avoids a false positive against a `isKeySpent[H(0,0)]`
    ///      entry that some future caller might inadvertently set.
    function _isKeySpent(
        WOTSPlus.WinternitzAddress memory key
    ) internal view returns (bool) {
        if (key.publicSeed == bytes32(0) || key.publicKeyHash == bytes32(0))
            return false;
        return Storage.layout().isKeySpent[_keyHash(key)];
    }

    /// @dev Reverts with `KeyInUse` if `key` has ever been installed in this wallet.
    ///      WOTS+ is one-time-use: any key whose public form has appeared on-chain
    ///      must be permanently retired, so installation is forbidden across the
    ///      board (any keyset, any single-key slot, any historical position).
    function _enforceUnspentKey(
        WOTSPlus.WinternitzAddress memory key
    ) internal view {
        if (_isKeySpent(key)) revert KeyInUse();
    }

    /// @dev Marks `key` as permanently burned in the monotonic `isKeySpent` index.
    ///      Called by every install path (`_safeAddKey`, `_setOwnershipKey`,
    ///      `_setDisasterRecoveryKey`). Never paired with a clearing operation —
    ///      removal from a live slot does NOT remove the burn flag.
    function _markKeySpent(
        WOTSPlus.WinternitzAddress memory key
    ) internal {
        Storage.layout().isKeySpent[_keyHash(key)] = true;
    }

    /// @dev Writes `key` to the wallet's ownership slot AND burns it in the
    ///      monotonic index. Single chokepoint for ownershipKey assignment so
    ///      no install site can forget to mark the key spent.
    function _setOwnershipKey(
        WOTSPlus.WinternitzAddress memory key
    ) internal {
        Storage.layout().ownershipKey = key;
        _markKeySpent(key);
    }

    /// @dev Writes `key` to the wallet's disaster recovery slot AND burns it
    ///      in the monotonic index. See `_setOwnershipKey`.
    function _setDisasterRecoveryKey(
        WOTSPlus.WinternitzAddress memory key
    ) internal {
        Storage.layout().disasterRecoveryKey = key;
        _markKeySpent(key);
    }

    /// @dev Reverts with `SameKey` if `a` and `b` are the same WOTS+ public key
    ///      (both fields equal). Called at the top of every rotation site before
    ///      WOTS+ verify so a "rotate to self" payload fails fast without burning
    ///      verify gas and without producing a misleading no-op-shaped state
    ///      transition that would still consume the one-time WOTS+ signing
    ///      capability. Also used for cross-input checks where two new keys in
    ///      the same call must be distinct.
    function _enforceDifferentKeys(
        WOTSPlus.WinternitzAddress memory a,
        WOTSPlus.WinternitzAddress memory b
    ) internal pure {
        if (a.publicSeed == b.publicSeed && a.publicKeyHash == b.publicKeyHash)
            revert SameKey();
    }

    /// @dev Wraps `set.add(key, MAX_KEYS)` with a global uniqueness pre-check, a
    ///      hard revert on bool=false, and a monotonic burn-mark on successful add.
    ///      The pre-check rejects any key already known to the wallet — including
    ///      keys that have been HISTORICALLY installed (per the `isKeySpent` index),
    ///      not just currently-live ones — with `KeyInUse`. Because that pre-check
    ///      subsumes the in-set duplicate case, a `false` return from `set.add` can
    ///      only mean cap excess, surfaced as `KeyAdditionFailed`. Marking the key
    ///      spent AFTER the add keeps the burn-on-failure semantics tight: if `set.add`
    ///      reverts (cap exceeded, library invariant violation), the key is not yet
    ///      burned and a retry with a smaller batch can still legitimately install it.
    function _safeAddKey(
        Keyset.WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress memory key
    ) internal {
        _enforceUnspentKey(key);
        if (!set.add(key, MAX_KEYS)) revert KeyAdditionFailed();
        _markKeySpent(key);
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
    ///
    ///      SECURITY: this is a self-consistency probe, not an authorization layer.
    ///      The `verifier` arrives in calldata alongside its own `verifySig`; this
    ///      function only checks that `verifySig` is valid for `verifier` over the
    ///      verification digest, NOT that `verifier` was pre-authorized anywhere
    ///      (no `verificationKeys` membership check, no factory registry lookup, no
    ///      governance allowlist). Anyone who can reach this code path can supply a
    ///      freshly generated verifier keypair and sign with it themselves.
    ///
    ///      What it actually proves: the new implementation's PQ verifier code path
    ///      is reachable and produces `true` on a well-formed input under whatever
    ///      scheme the new impl uses. A future impl migrating from WOTS+ to a
    ///      different PQ scheme (SPHINCS+, lattice-based, etc.) would override this
    ///      function to call its scheme's verify routine; the (verifier, verifySig)
    ///      pair in the upgrade payload would then be constructed under that scheme.
    ///      The actual upgrade authorization is the WOTS+ rotation on
    ///      `transactionKeys` / `recoveryKeys` that already ran in the caller; the
    ///      actual implementation gate is factory vetting.
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

    /// @dev Worker for `transferOwnership(bytes)`. A full re-initialization of
    ///      the wallet's PQ state on behalf of the new owner: the existing
    ///      `ownershipKey` authorizes a bundle of (newOwner, new `ownershipKey`,
    ///      new `disasterRecoveryKey`, new transactionKeys[5], new
    ///      recoveryKeys[10]); on success the existing ownership key rotates,
    ///      the disaster key is replaced, the transaction and recovery keysets
    ///      are cleared and repopulated, and the verification keyset is cleared
    ///      (the new owner re-seeds it out-of-band).
    ///
    ///      At the tail of this function — AFTER Solady's `_setOwner(newOwner)`
    ///      has committed — the wallet calls back into the factory via
    ///      `updateWalletOwner(oldOwner, newOwner)`. The factory verifies
    ///      `wallet.owner() == newOwner` as a load-bearing predicate that pins
    ///      the callback to this exact site; see `IQuipFactory.updateWalletOwner`
    ///      for the full attack tree.
    function _reinitializeAndTransferOwnership(
        bytes calldata payload
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
        bytes32 digest = Codec.transferOwnershipDigest(
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
        // Each single-key assignment is preceded by `_enforceUnspentKey` so the new
        // value cannot collide with anything currently in storage. Order matters:
        // ownership is enforced + assigned first, then disaster is enforced against the
        // freshly-set ownership. The keyset loops then run through `_safeAddKey`, which
        // re-checks against the new singles. Note this newly forbids
        // `newDisasterKey == oldDisasterKey` (caught here at the disaster-uniqueness
        // step, since the old value is still in storage) — a deliberate tightening for
        // WOTS+ one-time-use hygiene.
        _enforceUnspentKey(newOwnershipKey);
        _setOwnershipKey(newOwnershipKey);
        _enforceUnspentKey(newDisasterKey);
        _setDisasterRecoveryKey(newDisasterKey);
        _clearKeys($.transactionKeys);
        _clearKeys($.recoveryKeys);
        _clearKeys($.verificationKeys);
        for (uint256 i = 0; i < Codec.TRANSACTION_KEY_INIT_AMOUNT; ++i) {
            _safeAddKey($.transactionKeys, newTransactionKeys[i]);
        }
        for (uint256 i = 0; i < Codec.RECOVERY_KEY_AMOUNT; ++i) {
            _safeAddKey($.recoveryKeys, newRecoveryKeys[i]);
        }

        Ownable.transferOwnership(newOwner);

        // Notify the factory so its per-owner vaultIds set tracks the new
        // `owner()`. The factory reads the previous owner from its own
        // `walletOwner[msg.sender]` mapping. 
        // The pin-predicate `wallet.owner() == newOwner` ensures
        // this callback can only run at the tail of the flow, AFTER Solady
        // committed the transfer above. Reverts here roll back the whole
        // transferOwnership — partial state (owner updated, registry stale)
        // would be confusing.
        IQuipFactory(FACTORY).updateWalletOwner(newOwner);

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
        // Each single-key assignment is preceded by `_enforceUnspentKey` so the new
        // value cannot collide with anything currently in storage (relevant for the
        // `migrate` path, where the old singles + the still-populated verification
        // keyset are visible at this point). Order matters: disaster is enforced +
        // assigned first, then ownership is enforced against the freshly-set disaster.
        // The keyset loops then run through `_safeAddKey`, which re-checks against
        // both new singles.
        _enforceUnspentKey(disasterRecoveryKey);
        _setDisasterRecoveryKey(disasterRecoveryKey);
        _enforceUnspentKey(ownershipKey);
        _setOwnershipKey(ownershipKey);
        for (uint256 i = 0; i < Codec.TRANSACTION_KEY_INIT_AMOUNT; ++i) {
            _safeAddKey($.transactionKeys, transactionKeys[i]);
        }
        for (uint256 i = 0; i < Codec.RECOVERY_KEY_AMOUNT; ++i) {
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
        if ($.recoveryKeys.length() != Codec.RECOVERY_KEY_AMOUNT)
            revert IncorrectRecoveryKeyAmount();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     PRIVATES                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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

    /// @dev Reverts with `GuardedSlotTampered(slotIndex)` if any of the 7 guarded
    ///      slots has changed since `_snapshotGuardedSlots` was called. Unlike
    ///      `storageStoreGuard` (where the tampered slot is the caller-supplied
    ///      argument and thus already in calldata), here the offending slot was
    ///      written by the delegatecall body and is otherwise unobservable from
    ///      tx data without a re-simulate — so the index is surfaced for incident
    ///      response. Index mapping is documented on the error in `IQuipWallet`.
    function _assertGuardedSlotsUnchanged(
        bytes32[7] memory snapshot
    ) internal view {
        bytes4 selector = GuardedSlotTampered.selector;
        /// @solidity memory-safe-assembly
        assembly {
            function revertWithIndex(sel, idx) {
                mstore(0x00, sel)
                mstore(0x04, idx)
                revert(0x00, 0x24)
            }
            if iszero(eq(mload(snapshot), sload(_OWNER_SLOT))) {
                revertWithIndex(selector, 0)
            }
            if iszero(
                eq(
                    mload(add(snapshot, 0x20)),
                    sload(_ERC1967_IMPLEMENTATION_SLOT)
                )
            ) {
                revertWithIndex(selector, 1)
            }
            if iszero(eq(mload(add(snapshot, 0x40)), sload(_PQ_FACTORY_SLOT))) {
                revertWithIndex(selector, 2)
            }
            if iszero(
                eq(mload(add(snapshot, 0x60)), sload(_DISASTER_KEY_SEED_SLOT))
            ) {
                revertWithIndex(selector, 3)
            }
            if iszero(
                eq(mload(add(snapshot, 0x80)), sload(_DISASTER_KEY_HASH_SLOT))
            ) {
                revertWithIndex(selector, 4)
            }
            if iszero(
                eq(mload(add(snapshot, 0xa0)), sload(_OWNERSHIP_KEY_SEED_SLOT))
            ) {
                revertWithIndex(selector, 5)
            }
            if iszero(
                eq(mload(add(snapshot, 0xc0)), sload(_OWNERSHIP_KEY_HASH_SLOT))
            ) {
                revertWithIndex(selector, 6)
            }
        }
    }
}
