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

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec} from "../WOTSPlusCodec.sol";

/// @title IQuipWallet
/// @notice A smart-contract wallet whose operations are authorized by Winternitz one-time signatures,
///         providing post-quantum security for ETH transfers and arbitrary calls.
interface IQuipWallet {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERRORS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when the factory address is zero.
    error ZeroAddressFactory();
    /// @notice Thrown when the owner address is zero.
    error ZeroAddressOwner();
    /// @notice Thrown when the caller is not the immutable factory.
    error InvalidFactory();

    /// @notice Thrown when a Winternitz signature fails verification.
    error InvalidSignature();

    /// @notice Thrown when `renounceOwnership` is called (always reverts).
    error RenounceDisabled();
    /// @notice Thrown when the classical `withdrawDepositTo(address,uint256)` is called directly.
    /// @dev Only the WOTS+-authenticated `withdrawDepositTo(bytes)` path is permitted.
    error ClassicalWithdrawDisabled();
    /// @notice Thrown when the classical `transferOwnership(address)` is called directly.
    /// @dev Only the WOTS+-authenticated `transferOwnership(bytes)` path is permitted.
    error ClassicalTransferOwnershipDisabled();
    /// @notice Thrown when the classical `completeOwnershipHandover(address)` is called directly.
    /// @dev Only the WOTS+-authenticated `completeOwnershipHandover(bytes)` path is permitted.
    error ClassicalCompleteOwnershipHandoverDisabled();

    /// @notice Thrown when a provided key is already present in the target keyset,
    ///         or when a rotation's `nextKey` collides with the active transaction-key set.
    error DuplicateKey();
    /// @notice Thrown when a key being installed already exists somewhere in the wallet's
    ///         PQ state — any of the three keysets (`transactionKeys`, `recoveryKeys`,
    ///         `verificationKeys`) or either single key (`disasterRecoveryKey`,
    ///         `ownershipKey`). WOTS+ keys are one-time-use, so the same public key in two
    ///         slots means a single revealed signature burns it for both purposes.
    error KeyInUse();
    /// @notice Thrown when a rotation pair (currentKey, nextKey) collapses to the same
    ///         WOTS+ public key, or two new-key inputs in a multi-key flow are equal —
    ///         a "rotation to self" that would burn the WOTS+ signing capability without
    ///         producing a meaningful state change. Surfaced by `_enforceDifferentKeys`.
    error SameKey();
    /// @notice Thrown when a provided key is not present in the keyset that was expected to contain it.
    error UnknownKey();
    /// @notice Thrown when the underlying keyset `add` returns false during a rotation primitive
    ///         (`_safeAddKey`). Indicates a library/storage invariant violation, since callers gate
    ///         the add behind a prior `_enforceUncontained` or equivalent check. Catastrophic for a
    ///         one-time-signature scheme, so we revert loudly instead of emitting `KeyRotated` over
    ///         a no-op.
    error KeyAdditionFailed();
    /// @notice Thrown when the underlying keyset `remove` returns false during a rotation primitive
    ///         (`_safeRemoveKey`). Indicates a library/storage invariant violation, since callers gate
    ///         the remove behind a prior `_enforceContained` or `at(index)` proof of presence.
    ///         Catastrophic for a one-time-signature scheme — silent under-rotation would leave a
    ///         spent WOTS+ key live in the active set.
    error KeyRemovalFailed();
    /// @notice Thrown when an empty key array is provided to an add/refresh operation.
    error EmptyKeys();
    /// @notice Thrown when `refreshKeys` is called with `WOTSPlusCodec.KeyType.Transaction`.
    /// @dev Only `recoverWallet` may drain the transaction keyset.
    error RefreshTransactionForbidden();
    /// @notice Thrown when the number of recovery keys provided is incorrect.
    error IncorrectRecoveryKeyAmount();
    /// @notice Thrown when `replaceKeyAt(Transaction, index, newKey)` targets the same
    ///         key the caller is signing with. The auth rotation already consumes that
    ///         key; replacing it again in the same call is nonsensical.
    error ReplaceAuthKeyForbidden();
    /// @notice Thrown when `replaceKeyAt(Transaction, ..., newKey)` would install
    ///         `newKey == currentKey` — i.e. the key the caller is signing with.
    ///         The WOTS+ signature consumed during the auth rotation already
    ///         reveals roughly half of `currentKey`'s secret, so re-installing
    ///         it would seat a known-compromised key in the active set.
    error ReinstallSpentKeyForbidden();
    /// @notice Thrown when `migrate` is called outside the `upgradeToAndCall` context.
    error NotUpgrading();
    /// @notice Thrown when the number of transaction keys provided to `initialize`/`migrate` is incorrect.
    error IncorrectTransactionKeyAmount();

    /// @notice Thrown when the upgrade target's codehash is not in the factory's vetted set.
    error ImplementationNotVetted();
    /// @notice Thrown when the upgrade target's codehash has been deprecated.
    error ImplementationDeprecated();

    /// @notice Thrown when a provided `disasterRecoveryKey` does not match the stored one.
    error UnknownDisasterRecoveryKey();

    /// @notice Thrown when a provided `ownershipKey` does not match the stored one,
    ///         or when a replacement `ownershipKey` has a zero component.
    error UnknownOwnershipKey();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a WOTS+ key is rotated in place (remove-then-add) within
    ///         one of the wallet's keysets.
    /// @dev Emitted by `_rotateKeys` on every key-consumption path — most callers
    ///      rotate within the transaction keyset, but `recoveryUpgrade` rotates within
    ///      the recovery keyset. The event alone does not distinguish which keyset was
    ///      touched; the surrounding op-specific event (e.g. `RecoveryUpgrade`,
    ///      `ExecutionSucceeded`) provides that context.
    /// @param oldKey The removed Winternitz public key.
    /// @param newKey The installed Winternitz public key.
    event KeyRotated(
        WOTSPlus.WinternitzAddress oldKey,
        WOTSPlus.WinternitzAddress newKey
    );

    /// @notice Emitted when an execution call succeeds.
    /// @param target The recipient or contract address.
    /// @param value The ETH value sent to the target.
    /// @param dataHash The keccak256 hash of the calldata.
    event ExecutionSucceeded(address target, uint256 value, bytes32 dataHash);

    /// @notice Emitted when a wallet is initialized with its factory, owner, and keys.
    /// @param factory The QuipFactory that created this wallet.
    /// @param owner The classical owner address.
    /// @param transactionKeys The initial set of 5 transaction keys.
    /// @param recoveryKeys The initial set of 10 recovery keys.
    event WalletInitialized(
        address indexed factory,
        address indexed owner,
        WOTSPlus.WinternitzAddress[5] transactionKeys,
        WOTSPlus.WinternitzAddress[10] recoveryKeys
    );

    /// @notice Emitted when the wallet is recovered using a recovery key.
    /// @param recoveryKey The recovery key that authorized (and was burned by) the recovery.
    /// @param newRecoveryKey The replacement recovery key installed in the recovery keyset
    ///        in the burned key's place — preserves the wallet's recovery capacity.
    /// @param newTransactionKey The single transaction key seeded during recovery (the
    ///        transaction keyset is cleared and reseeded with this key alone).
    event PqRecovery(
        WOTSPlus.WinternitzAddress recoveryKey,
        WOTSPlus.WinternitzAddress newRecoveryKey,
        WOTSPlus.WinternitzAddress newTransactionKey
    );

    /// @notice Emitted when the wallet is rescued via the disaster recovery key.
    /// @param oldDisasterRecoveryKey The consumed disaster recovery key.
    /// @param newDisasterRecoveryKey The installed replacement disaster recovery key.
    /// @param newTransactionKeysHash `keccak256(abi.encode(newTransactionKeys))` — identifies
    ///        the installed transaction-key batch without ballooning the event payload.
    /// @param newRecoveryKeysHash `keccak256(abi.encode(newRecoveryKeys))` — identifies the
    ///        installed recovery-key batch.
    event WalletSaved(
        WOTSPlus.WinternitzAddress oldDisasterRecoveryKey,
        WOTSPlus.WinternitzAddress newDisasterRecoveryKey,
        bytes32 newTransactionKeysHash,
        bytes32 newRecoveryKeysHash
    );

    /// @notice Emitted when ownership is transferred (or handed over) and the PQ state is
    ///         fully re-initialized for the incoming owner.
    /// @param oldOwnershipKey The consumed ownership key.
    /// @param newOwnershipKey The installed replacement ownership key.
    /// @param newOwner The classical address that now owns the wallet.
    /// @param newDisasterRecoveryKey The installed replacement disaster recovery key.
    /// @param newTransactionKeysHash `keccak256(abi.encode(newTransactionKeys))`.
    /// @param newRecoveryKeysHash `keccak256(abi.encode(newRecoveryKeys))`.
    event OwnershipReinitialized(
        WOTSPlus.WinternitzAddress oldOwnershipKey,
        WOTSPlus.WinternitzAddress newOwnershipKey,
        address newOwner,
        WOTSPlus.WinternitzAddress newDisasterRecoveryKey,
        bytes32 newTransactionKeysHash,
        bytes32 newRecoveryKeysHash
    );

    /// @notice Emitted when keys are added to a keyset via `addKeys`.
    /// @param kind The keyset that received the additions.
    /// @param nextKey The installed transaction key after rotation.
    /// @param count The number of keys added.
    event KeysAdded(
        WOTSPlusCodec.KeyType indexed kind,
        WOTSPlus.WinternitzAddress nextKey,
        uint256 count
    );

    /// @notice Emitted when a keyset is cleared and replaced via `refreshKeys`.
    /// @param kind The keyset that was refreshed.
    /// @param nextKey The installed transaction key after rotation.
    event KeysRefreshed(
        WOTSPlusCodec.KeyType indexed kind,
        WOTSPlus.WinternitzAddress nextKey
    );

    /// @notice Emitted when PQ state is migrated during an upgrade.
    /// @param transactionKeysHash `keccak256(abi.encode(transactionKeys))` of the
    ///        migrated transaction-key set. The full array is not emitted because
    ///        topics + data would balloon the upgrade calldata; a hash is the
    ///        cheapest useful commitment — off-chain indexers can recompute it from
    ///        the migrator payload, which is itself available via calldata.
    event WalletMigrated(bytes32 transactionKeysHash);

    /// @notice Emitted when a recovery key authorizes an emergency implementation upgrade.
    /// @param newImplementation The new implementation address.
    /// @param recoveryKey The recovery key that authorized the upgrade.
    event RecoveryUpgrade(
        address indexed newImplementation,
        WOTSPlus.WinternitzAddress recoveryKey
    );

    /// @notice Emitted when a key at a specific index is replaced via `replaceKeyAt`.
    /// @param kind The keyset whose entry was replaced.
    /// @param index The index that was replaced.
    /// @param oldKey The removed key.
    /// @param newKey The replacement key.
    /// @param nextKey The installed transaction key after the auth rotation.
    event KeyReplaced(
        WOTSPlusCodec.KeyType indexed kind,
        uint256 index,
        WOTSPlus.WinternitzAddress oldKey,
        WOTSPlus.WinternitzAddress newKey,
        WOTSPlus.WinternitzAddress nextKey
    );

    /// @notice Emitted when the inner call of an ERC-4337 execution reverts but key rotation commits.
    /// @param target The target of the failed call.
    /// @param value The ETH value attempted.
    /// @param dataHash The keccak256 hash of the calldata.
    /// @param result The revert data from the failed call.
    event ExecutionReverted(
        address target,
        uint256 value,
        bytes32 dataHash,
        bytes result
    );

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          FUNCTIONS                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Disabled; always reverts with `RenounceDisabled`.
    function renounceOwnership() external payable;

    /// @notice Upgrades the wallet to a new implementation, verifying two PQ signatures and
    ///         optionally migrating state.
    /// @dev First verifies the upgrade authorization against `currentKey` using pqSig.
    ///      Then delegatecalls `verifyUpgrade` on the new implementation, which independently
    ///      verifies a second signature from the verifier key embedded in the payload.
    ///      Optionally calls `migrate` if the payload includes migration data. Finally delegates
    ///      to the parent `upgradeToAndCall` with empty calldata.
    /// @param newImplementation The address of the new implementation contract.
    /// @param data Packed upgrade data: [0:64) currentKey, [64:128) nextKey,
    ///      [128:2272) pqSig, [2272:2336) verifier, [2336:4480) verifySig,
    ///      [4480] shouldMigrate, [4481:5569) migratorPayload (new init layout, 1088 bytes).
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) external payable;

    /// @notice Verifies a PQ signature from the new implementation's verifier key.
    /// @dev Called via delegatecall from `upgradeToAndCall` on the new implementation.
    ///      Factory vetting is the caller's responsibility; this function performs only
    ///      scheme-specific verification. Future implementations may use a different PQ scheme.
    /// @param newImplementation The address of the new implementation being upgraded to.
    /// @param data Packed upgrade payload; verifier at [2272:2336), verifySig at [2336:4480).
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view;

    /// @notice Verifies a PQ signature from the new implementation's verifier key
    ///         for the recoveryUpgrade path.
    /// @dev Called via delegatecall from `recoveryUpgrade` on the new implementation.
    ///      Shares the same (currentKey, newKey, pqSig) auth shape as `upgradeToAndCall`
    ///      since the recovery path now rotates the consumed recovery key in place.
    /// @param newImplementation The address of the new implementation being upgraded to.
    /// @param data Packed recoveryUpgrade payload; verifier at [2272:2336), verifySig at [2336:4480).
    function verifyRecoveryUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view;

    /// @notice Initializes the wallet with its classical owner, disaster recovery key,
    ///         ownership key, transaction keys, and recovery keys.
    /// @dev Can only be called once by the FACTORY. Uses Solady's `initializer` modifier.
    ///      Payload layout: [0:64) disasterRecoveryKey, [64:128) ownershipKey,
    ///      [128:448) transactionKeys (5 x 64), [448:1088) recoveryKeys (10 x 64).
    /// @param newOwner The classical owner address.
    /// @param payload Packed init data (1088 bytes).
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) external;

    /// @notice Re-initializes the PQ state (disaster recovery key + ownership key + transaction
    ///         + recovery keys) during an upgrade.
    /// @dev Only callable by the classical owner. Called via delegatecall from upgradeToAndCall
    ///      so that it executes against proxy storage.
    ///      Payload layout matches `initialize` (1088 bytes).
    /// @param payload Packed migration data matching the init layout.
    function migrate(bytes calldata payload) external;

    /// @notice Executes a post-quantum authenticated operation: either a pure ETH transfer
    ///         or an arbitrary contract call.
    /// @dev Only callable by the classical owner. The fee is deducted from the wallet balance
    ///      and sent to the factory. The fee is committed in the signed digest so the factory
    ///      owner cannot front-run the transaction by raising the fee.
    ///      For pure transfers (data is empty), uses SafeTransferLib.
    ///      For contract calls (data is non-empty), uses LibCall.callContract.
    ///      Consumes `currentKey` and installs `nextKey` upon success.
    ///      Payload layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig,
    ///      [2272:2304) target, [2304:2336) value, [2336:...) data.
    /// @param payload Packed execute data (>= 2336 bytes).
    /// @return The data returned by the call (empty for pure transfers).
    function execute(
        bytes calldata payload
    ) external payable returns (bytes memory);

    /// @notice Withdraws ETH from the wallet's EntryPoint deposit, authorized by a WOTS+ signature.
    /// @dev Only callable by the classical owner. Consumes `currentKey` and installs `nextKey`,
    ///      then delegates to Solady's withdrawDepositTo which calls withdrawTo on the EntryPoint.
    ///      No fee is charged.
    ///      Payload layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig,
    ///      [2272:2304) to, [2304:2336) amount.
    /// @param payload Packed withdrawDeposit data (2336 bytes).
    function withdrawDepositTo(bytes calldata payload) external payable;

    /// @notice Transfers ownership to `newOwner` and fully re-initializes PQ state.
    /// @dev Authorized by the wallet's dedicated `ownershipKey` — a guarded WOTS+ slot
    ///      separate from the transaction keyset. The old owner knows all the current PQ key
    ///      material by virtue of having used it, so ownership transfer is treated as a full
    ///      re-initialization: the caller supplies a fresh `ownershipKey`, `disasterRecoveryKey`,
    ///      transaction keyset, and recovery keyset that the incoming owner alone controls.
    ///      The existing verification keyset is cleared (the new owner re-seeds it as needed).
    ///      The existing `ownershipKey` rotates to the supplied replacement (one-time-use).
    ///      Payload layout: [0:64) currentOwnershipKey, [64:128) newOwnershipKey,
    ///      [128:2272) pqSig, [2272:2304) newOwner, [2304:2368) newDisasterKey,
    ///      [2368:2688) newTransactionKeys[5], [2688:3328) newRecoveryKeys[10].
    /// @param payload Packed ownership-transfer data (3328 bytes).
    function transferOwnership(bytes calldata payload) external payable;

    /// @notice Completes a two-step ownership handover to `pendingOwner` and fully re-initializes
    ///         PQ state for the new owner.
    /// @dev Same re-initialization semantics as `transferOwnership`; the difference is only the
    ///      domain tag on the signed digest (so a signature cannot be lifted between the two
    ///      code paths) and the final call into Solady's `completeOwnershipHandover`.
    ///      Payload layout matches `transferOwnership` (3328 bytes).
    /// @param payload Packed ownership-transfer data (3328 bytes).
    function completeOwnershipHandover(bytes calldata payload) external payable;

    /// @notice Returns the current execute fee as set by the factory.
    /// @return The execute fee in wei.
    function getExecuteFee() external view returns (uint256);

    /// @notice Returns the address of the QuipFactory that created this wallet.
    /// @return The factory address.
    function quipFactory() external view returns (address payable);

    /// @notice Returns the number of keys in the selected keyset.
    /// @param kind The keyset to query.
    /// @return The number of active keys in that keyset.
    function keyCount(WOTSPlusCodec.KeyType kind) external view returns (uint256);

    /// @notice Returns the key at a given index within the selected keyset.
    /// @param kind The keyset to query.
    /// @param index The zero-based index into the keyset.
    /// @return The Winternitz public key stored at `index`.
    function keyAt(
        WOTSPlusCodec.KeyType kind,
        uint256 index
    ) external view returns (WOTSPlus.WinternitzAddress memory);

    /// @notice Returns whether the given Winternitz address is a member of the selected keyset.
    /// @param kind The keyset to query.
    /// @param key The Winternitz public key to check.
    function isKey(
        WOTSPlusCodec.KeyType kind,
        WOTSPlus.WinternitzAddress calldata key
    ) external view returns (bool);

    /// @notice Recovers the wallet using a pre-registered recovery key.
    /// @dev Drains the current transaction-key set and seeds exactly one new key.
    ///      Payload layout: [0:64) recoveryKey, [64:128) newTransactionKey, [128:2272) pqSig.
    /// @param payload Packed recoverWallet data (2272 bytes).
    function recoverWallet(bytes calldata payload) external;

    /// @notice Last-resort rescue: resets `transactionKeys` and `recoveryKeys` using the
    ///         wallet's disaster recovery key. Leaves `verificationKeys` and `owner()` intact.
    /// @dev Authorized solely by a WOTS+ signature from the stored disaster recovery key.
    ///      The key rotates on use — the payload carries a `newDisasterRecoveryKey` that
    ///      replaces the consumed one. No `onlyOwner` gate: if the classical owner is also
    ///      compromised, this path must still be reachable.
    ///
    ///      Payload layout: [0:64) currentDisasterKey, [64:128) newDisasterKey,
    ///      [128:2272) pqSig, [2272:2592) newTransactionKeys[5], [2592:3232) newRecoveryKeys[10].
    /// @param payload Packed saveWallet data (3232 bytes).
    function saveWallet(bytes calldata payload) external;

    /// @notice Appends new keys to the target keyset, authorized by a WOTS+ signature.
    /// @dev Consumes `currentKey` / installs `nextKey` from the transaction keyset.
    ///      For `WOTSPlusCodec.KeyType.Transaction`, the extras are appended to the active transaction set;
    ///      for `Recovery` / `Verification`, the target set is extended.
    ///      The transaction rotation is committed before the target-set write.
    ///      Payload layout: [0:32) kind, [32:96) currentKey, [96:160) nextKey,
    ///      [160:2304) pqSig, [2304:...) keys (N x 64).
    /// @param payload Packed keyManagement data (>= 2304 bytes).
    function addKeys(bytes calldata payload) external;

    /// @notice Clears the target keyset and installs a fresh batch.
    /// @dev Reverts with `RefreshTransactionForbidden` when `kind == WOTSPlusCodec.KeyType.Transaction` —
    ///      only `recoverWallet` may drain the transaction keyset.
    ///      Consumes `currentKey` / installs `nextKey` from the transaction keyset.
    ///      Payload layout: [0:32) kind, [32:96) currentKey, [96:160) nextKey,
    ///      [160:2304) pqSig, [2304:...) keys (N x 64).
    /// @param payload Packed keyManagement data (>= 2304 bytes).
    function refreshKeys(bytes calldata payload) external;

    /// @notice Emergency upgrade authorized by a recovery key, without migration.
    /// @dev Verifies the recovery-key signature, delegatecalls `verifyRecoveryUpgrade` on
    ///      the new implementation, then rotates the consumed recovery key in place —
    ///      `currentRecoveryKey` is removed and `newRecoveryKey` is installed so the
    ///      recovery keyset size stays stable. No transaction-key rotation or migration
    ///      is performed.
    ///      Payload layout: [0:64) currentRecoveryKey, [64:128) newRecoveryKey,
    ///      [128:2272) pqSig, [2272:2336) verifier, [2336:4480) verifySig.
    /// @param newImplementation The address of the new implementation contract.
    /// @param payload Packed recovery upgrade data (4480 bytes).
    function recoveryUpgrade(
        address newImplementation,
        bytes calldata payload
    ) external;

    /// @notice Replaces a single key at the given index in the keyset selected by
    ///         `kind`. Authorized by a transaction-key rotation.
    /// @dev Removes the key at `index` and installs `newKey` in its place on the
    ///      target keyset. The auth rotation (currentKey → nextKey) always runs on
    ///      the transaction keyset. For `kind == Transaction` the target keyset is
    ///      the same as the auth keyset — the key at `index` must NOT equal
    ///      `currentKey` (reverts with `ReplaceAuthKeyForbidden`). The two
    ///      operations ordering is read-oldKey → auth-rotate → remove-oldKey →
    ///      add-newKey, so `oldKey` is captured from the pre-rotation snapshot.
    ///      Payload layout: [0:32) kind, [32:96) currentKey, [96:160) nextKey,
    ///      [160:2304) pqSig, [2304:2336) index, [2336:2400) newKey.
    /// @param payload Packed replaceKeyAt data (2400 bytes).
    function replaceKeyAt(bytes calldata payload) external;

    /// @notice Returns the implementation version of this wallet.
    /// @dev Reads the ERC-1967 implementation slot and queries the factory for
    ///      the index of its codehash in the vetted set.
    /// @return The index in the factory's vetted set, or `type(uint256).max` if not found.
    function version() external view returns (uint256);
}
