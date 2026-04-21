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

    /// @notice Thrown when the wallet balance is insufficient for the requested operation.
    /// @param requested The amount required.
    /// @param available The current balance.
    error InsufficientBalance(uint256 requested, uint256 available);
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
    /// @notice Thrown when a provided key is not present in the keyset that was expected to contain it.
    error UnknownKey();
    /// @notice Thrown when an empty key array is provided to an add/refresh operation.
    error EmptyKeys();
    /// @notice Thrown when `refreshKeys` is called with `WOTSPlusCodec.KeyType.Transaction`.
    /// @dev Only `recoverWallet` may drain the transaction keyset.
    error RefreshTransactionForbidden();
    /// @notice Thrown when the number of recovery keys provided is incorrect.
    error IncorrectRecoveryKeyAmount();
    /// @notice Thrown when a verification key index is out of bounds.
    error VerificationKeyIndexOutOfBounds();
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
    /// @notice Thrown when a rotation's new `disasterRecoveryKey` equals the current one,
    ///         which would violate WOTS+ one-time-use on the disaster recovery slot.
    error DuplicateDisasterRecoveryKey();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a transaction key is rotated (remove-then-add).
    /// @dev Emitted by `_rotateKeys` on every transaction-key consumption path.
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
    /// @param recoveryKey The recovery key that authorized the recovery.
    /// @param newTransactionKey The single transaction key seeded during recovery.
    event PqRecovery(
        WOTSPlus.WinternitzAddress recoveryKey,
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

    /// @notice Emitted when a verification key at a specific index is replaced.
    /// @param index The index that was replaced.
    /// @param oldKey The removed key.
    /// @param newKey The replacement key.
    /// @param nextKey The installed transaction key after rotation.
    event VerificationKeyReplaced(
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
    ///      [4480] shouldMigrate, [4481:5505) migratorPayload (new init layout, 1024 bytes).
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
    ///      Differs from `verifyUpgrade` only in payload layout (recovery payloads omit
    ///      the currentKey/nextKey pair, so the verifier sits at offset 2208 rather than 2272).
    /// @param newImplementation The address of the new implementation being upgraded to.
    /// @param data Packed recoveryUpgrade payload; verifier at [2208:2272), verifySig at [2272:4416).
    function verifyRecoveryUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view;

    /// @notice Initializes the wallet with its classical owner, disaster recovery key,
    ///         transaction keys, and recovery keys.
    /// @dev Can only be called once by the FACTORY. Uses Solady's `initializer` modifier.
    ///      Payload layout: [0:64) disasterRecoveryKey, [64:384) transactionKeys (5 x 64),
    ///      [384:1024) recoveryKeys (10 x 64).
    /// @param newOwner The classical owner address.
    /// @param payload Packed init data (1024 bytes).
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) external;

    /// @notice Re-initializes the PQ state (disaster recovery key + transaction + recovery keys)
    ///         during an upgrade.
    /// @dev Only callable by the classical owner. Called via delegatecall from upgradeToAndCall
    ///      so that it executes against proxy storage.
    ///      Payload layout matches `initialize` (1024 bytes).
    /// @param payload Packed migration data matching the init layout.
    function migrate(bytes calldata payload) external;

    /// @notice Rotates a transaction key without any other side effects.
    /// @dev Only callable by the classical owner. The signature must be valid over the
    ///      concatenation of the current and new public key components.
    ///      Payload layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig.
    /// @param payload Packed changeTransactionKey data (2272 bytes).
    function changeTransactionKey(bytes calldata payload) external;

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

    /// @notice Transfers classical ownership to `newOwner`, authorized by a WOTS+ signature.
    /// @dev Only callable by the classical owner. Consumes `currentKey` / installs `nextKey`,
    ///      then delegates to the parent `Ownable.transferOwnership`.
    ///      Payload layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig,
    ///      [2272:2304) newOwner.
    /// @param payload Packed ownership transfer data (2304 bytes).
    function transferOwnership(bytes calldata payload) external payable;

    /// @notice Completes a two-step ownership handover to `pendingOwner`, authorized by a WOTS+ signature.
    /// @dev Only callable by the classical owner. Consumes `currentKey` / installs `nextKey`,
    ///      then delegates to the parent `Ownable.completeOwnershipHandover`.
    ///      Payload layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig,
    ///      [2272:2304) pendingOwner.
    /// @param payload Packed ownership transfer data (2304 bytes).
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
    /// @dev Verifies the recovery key signature, then delegatecalls `verifyUpgrade` on the
    ///      new implementation. No transaction-key rotation or migration is performed.
    ///      Payload layout: [0:64) recoveryKey, [64:2208) pqSig,
    ///      [2208:2272) verifier, [2272:4416) verifySig.
    /// @param newImplementation The address of the new implementation contract.
    /// @param payload Packed recovery upgrade data (4416 bytes).
    function recoveryUpgrade(
        address newImplementation,
        bytes calldata payload
    ) external;

    /// @notice Replaces a single verification key at the given index.
    /// @dev Payload layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig,
    ///      [2272:2304) index, [2304:2368) newKey.
    /// @param payload Packed replace-verification-key data (2368 bytes).
    function replaceVerificationKeyAt(bytes calldata payload) external;

    /// @notice Returns the implementation version of this wallet.
    /// @dev Reads the ERC-1967 implementation slot and queries the factory for
    ///      the index of its codehash in the vetted set.
    /// @return The index in the factory's vetted set, or `type(uint256).max` if not found.
    function version() external view returns (uint256);
}
