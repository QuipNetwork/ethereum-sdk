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
/// @notice A smart-contract wallet whose operations are authorized by Winternitz
///         one-time signatures, providing post-quantum security for ETH transfers
///         and arbitrary calls.
interface IQuipWallet {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ERRORS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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
    /// @notice Thrown when any of Solady's inherited two-step ownership handover
    ///         entry points (`requestOwnershipHandover`, `cancelOwnershipHandover`,
    ///         the classical `completeOwnershipHandover(address)`) is called.
    /// @dev This wallet does not support two-step ownership handover. All ownership
    ///      transfers MUST go through the WOTS+-authenticated `transferOwnership(bytes)`
    ///      path, which atomically rotates the PQ ownership key, re-seeds the
    ///      keysets, commits Solady's `_setOwner(newOwner)`, and notifies the
    ///      factory via `updateWalletOwner`. The two-step pattern's typo-mitigation
    ///      value is subsumed by the WOTS+ signature already committing
    ///      cryptographically to `newOwner` in the signed digest.
    error OwnershipHandoverDisabled();

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
    /// @notice Thrown when a provided key is not present in the keyset that
    ///         was expected to contain it.
    error UnknownKey();
    /// @notice Thrown when the underlying keyset `add` returns false during a rotation primitive
    ///         (`_safeAddKey`). Indicates a library/storage invariant violation, since callers gate
    ///         the add behind a prior `_enforceUncontained` or equivalent check. Catastrophic for a
    ///         one-time-signature scheme, so we revert loudly instead of emitting `KeyRotated` over
    ///         a no-op.
    error KeyAdditionFailed();
    /// @notice Thrown when the underlying keyset `remove` returns false during a rotation primitive
    ///         (`_safeRemoveKey`). Indicates a library/storage invariant violation,
    ///         since callers gate
    ///         the remove behind a prior `_enforceContained` or `at(index)` proof of presence.
    ///         Catastrophic for a one-time-signature scheme — silent under-rotation would leave a
    ///         spent WOTS+ key live in the active set.
    error KeyRemovalFailed();
    /// @notice Thrown when an empty key array is provided to an add/refresh operation.
    error EmptyKeys();
    /// @notice Thrown when `refreshKeys` is called with `WOTSPlusCodec.KeyType.Transaction`.
    /// @dev Only `recoverWallet` may drain the transaction keyset.
    error RefreshTransactionForbidden();
    /// @notice Thrown by `replaceKeys` when the caller-declared `signingKind` is
    ///         `WOTSPlusCodec.KeyType.Verification`. Verification keys are not
    ///         signing-capable; only Transaction or Recovery may authorize.
    error InvalidSigningKeyset();
    /// @notice Thrown by `replaceKeys` if the post-decode array lengths disagree
    ///         with the caller-supplied `n`. The codec already enforces
    ///         `oldKeys.length == newKeys.length == n` during decode; this is
    ///         a belt-and-suspenders re-assertion at the wallet level so a
    ///         future codec refactor that drops the check fails loudly here.
    /// @dev Distinct from `WOTSPlusCodec.MalformedPayload(expected, actual)`,
    ///      which surfaces on bytes-level length / stride mismatches inside
    ///      the decoder.
    error MalformedPayload();
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
    /// @notice Thrown when the number of transaction keys provided to
    ///         `initialize`/`migrate` is incorrect.
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

    /// @notice Thrown when a delegatecall body modified one of the seven slots that
    ///         `delegateExecuteGuard` snapshots and re-checks. The tampered slot is
    ///         not in calldata, so the index is surfaced for incident response.
    /// @param slotIndex 0=owner, 1=ERC-1967 impl, 2=quipFactory,
    ///                  3=disasterRecoveryKey seed, 4=disasterRecoveryKey hash,
    ///                  5=ownershipKey seed, 6=ownershipKey hash.
    error GuardedSlotTampered(uint8 slotIndex);

    /// @notice Thrown when `storageStore` is invoked with a `storageSlot` that
    ///         falls within the set of PQ-protected slots (owner, ERC-1967 impl,
    ///         quipFactory, both disaster-recovery-key slots, both ownership-key
    ///         slots).
    /// @dev No payload: the guarded slot is the caller-supplied `storageSlot`
    ///      argument and is already visible in calldata, so duplicating it in
    ///      revert data buys nothing. The selector alone distinguishes this
    ///      branch from other reverts (e.g. `Unauthorized`) for trace tooling.
    error GuardedSlotWriteDenied();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         EVENTS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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
    event ExecutionSucceeded(
        address indexed target,
        uint256 value,
        bytes32 dataHash
    );

    /// @notice Emitted in place of `ExecutionSucceeded` when `execute(bytes)` is
    ///         signed with `value == 0 && data.length == 0`.
    /// @dev Empty executes are not an intended key-burn primitive, but a user
    ///      who signs one still pays the fee and burns the consumed
    ///      transaction key (rotation commits inside `_verifyAndRotate` before
    ///      the inner call would run). This event makes the no-op conspicuous
    ///      so an indexer / wallet UI can distinguish it from a real transfer
    ///      with `target == 0 && value == 0`.
    /// @param currentKey The consumed (rotated-out) transaction key.
    /// @param nextKey The replacement transaction key installed in its place.
    event KeyRotationOnly(
        WOTSPlus.WinternitzAddress currentKey,
        WOTSPlus.WinternitzAddress nextKey
    );

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
        address indexed newOwner,
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
    event WalletMigrated(bytes32 indexed transactionKeysHash);

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
        uint256 indexed index,
        WOTSPlus.WinternitzAddress oldKey,
        WOTSPlus.WinternitzAddress newKey,
        WOTSPlus.WinternitzAddress nextKey
    );

    /// @notice Emitted when an N-for-N key swap via `replaceKeys` succeeds.
    /// @dev Emitted after both the signing-keyset rotation and the target-set
    ///      remove+add loop have committed. `kind` and `signingKind` together
    ///      identify which of the 6 (signingKind × targetKind) variants ran.
    /// @param kind The target keyset whose entries were swapped.
    /// @param signingKind The keyset that authorized the swap (Tx or Recovery).
    /// @param currentKey The consumed (rotated-out) key from `signingKind` set.
    /// @param nextKey The replacement key installed in `signingKind` set.
    /// @param oldKeys The N keys removed from the target keyset.
    /// @param newKeys The N keys installed in the target keyset.
    event KeysReplaced(
        WOTSPlusCodec.KeyType indexed kind,
        WOTSPlusCodec.KeyType indexed signingKind,
        WOTSPlus.WinternitzAddress currentKey,
        WOTSPlus.WinternitzAddress nextKey,
        WOTSPlus.WinternitzAddress[] oldKeys,
        WOTSPlus.WinternitzAddress[] newKeys
    );

    /// @notice Emitted when the inner call of an ERC-4337 execution reverts but
    ///         key rotation commits.
    /// @param target The target of the failed call.
    /// @param value The ETH value attempted.
    /// @param dataHash The keccak256 hash of the calldata.
    /// @param result The revert data from the failed call.
    event ExecutionReverted(
        address indexed target,
        uint256 value,
        bytes32 dataHash,
        bytes result
    );

    /// @notice Discriminates the four reasons `_validateSignature` may return
    ///         `validationData == 1` (signature failure) to the EntryPoint.
    /// @dev Surfaced to off-chain simulators (`eth_call` / `debug_traceCall`)
    ///      via `UserOpValidationRejected` since ERC-4337 forbids reverting
    ///      with a reason from `validateUserOp`.
    enum UserOpValidationFailure {
        ZeroNextKey,
        StaleCurrentKey,
        NextKeyAlreadyInUse,
        InvalidSignature
    }

    /// @notice Emitted on each `validationData == 1` exit of `_validateSignature`.
    /// @dev On-chain this event is rolled back when the EntryPoint reverts the
    ///      UserOp on signature failure, but bundlers / simulators observe it
    ///      via `debug_traceCall` traces during pre-flight simulation. Provides
    ///      operators a typed reason code for triaging failed sponsored UserOps
    ///      without requiring a manual trace dive.
    /// @param reason The classification of the rejection.
    event UserOpValidationRejected(UserOpValidationFailure indexed reason);

    /// @notice Discriminates the four reasons `isValidSignature` may return the
    ///         ERC-1271 failure magic (`0xffffffff`), plus an `Ok` success
    ///         sentinel surfaced by `debugIsValidSignature`.
    /// @dev `isValidSignature` is `view`, so unlike the ERC-4337 paths there is
    ///      no event channel for these reason codes — `debugIsValidSignature`
    ///      is the only way to recover the specific failure branch off-chain.
    enum Erc1271ValidationResult {
        Ok,
        BadSignatureLength,
        InvalidEcdsaSignature,
        UnknownVerifier,
        InvalidPqSignature
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        STRUCTS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Snapshot of every WOTS+ key the wallet currently holds.
    /// @dev Returned by `getAllKeys()` to let off-chain callers fetch the
    ///      full PQ state in a single read. Mirrors the storage layout in
    ///      `WOTSPlusStorage.Layout`: two single-slot keys plus three
    ///      enumerable keysets.
    /// @param disasterRecoveryKey The current `disasterRecoveryKey`.
    /// @param ownershipKey The current `ownershipKey`.
    /// @param transactionKeys Every active transaction key, in storage order.
    /// @param recoveryKeys Every active recovery key, in storage order.
    /// @param verificationKeys Every active verification key, in storage order.
    struct AllKeys {
        WOTSPlus.WinternitzAddress disasterRecoveryKey;
        WOTSPlus.WinternitzAddress ownershipKey;
        WOTSPlus.WinternitzAddress[] transactionKeys;
        WOTSPlus.WinternitzAddress[] recoveryKeys;
        WOTSPlus.WinternitzAddress[] verificationKeys;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Disabled; always reverts with `RenounceDisabled`.
    function renounceOwnership() external payable;

    /// @notice Upgrades the wallet to a new implementation, gated by a WOTS+
    ///         signature from the transaction keyset plus a scheme-compatibility
    ///         probe against the new implementation, and optionally migrating state.
    /// @dev Authorization order:
    ///        1. Factory vetting check — `newImplementation` must be in the factory's
    ///           vetted set and not deprecated. This is the actual gate on which
    ///           implementations can be reached.
    ///        2. WOTS+ rotation on `transactionKeys` using (currentKey, nextKey, pqSig).
    ///           This is the actual upgrade authorization.
    ///        3. Delegatecall to `newImplementation.verifyUpgrade(...)` — a
    ///           scheme-compatibility probe (NOT a second authorization factor).
    ///           See `verifyUpgrade` natspec for what this proves and what it does not.
    ///      Optionally calls `migrate` if the payload's `shouldMigrate` byte is set.
    ///      Finally delegates to the parent `upgradeToAndCall` with empty calldata.
    /// @param newImplementation The address of the new implementation contract.
    /// @param data Packed upgrade data: [0:64) currentKey, [64:128) nextKey,
    ///      [128:2272) pqSig, [2272:2336) verifier, [2336:4480) verifySig,
    ///      [4480] shouldMigrate, [4481:5569) migratorPayload (new init layout, 1088 bytes).
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) external payable;

    /// @notice Scheme-compatibility probe run on the new implementation during
    ///         `upgradeToAndCall`. NOT a second authorization factor.
    /// @dev Called via delegatecall from `upgradeToAndCall` so the new implementation's
    ///      bytecode executes against the wallet's storage. The (verifier, verifySig)
    ///      pair in the payload is supplied by the upgrade caller and is constructed
    ///      under whatever signature scheme the new implementation uses. The new impl's
    ///      `_verifyImplementationSig` then runs that scheme's verify routine against
    ///      the pair and reverts if it returns false.
    ///
    ///      What this proves:
    ///        - The new implementation's signature-verification code path is reachable
    ///          and produces `true` on a well-formed input under its declared scheme.
    ///          This is the forward-compatibility hook for a future migration from
    ///          WOTS+ to a different post-quantum scheme (e.g. SPHINCS+, a lattice
    ///          scheme): an impl whose verifier code is missing, broken, or returns
    ///          false unconditionally will fail this check and the upgrade reverts.
    ///
    ///      What this does NOT prove:
    ///        - That the verifier was pre-authorized by wallet state, factory policy,
    ///          governance, or any stored allowlist. The verifier keypair is generated
    ///          by the caller; they sign with it themselves. The check is purely
    ///          self-consistent.
    ///        - That an independent third party approved the upgrade. The actual
    ///          upgrade authorization is the WOTS+ rotation on `transactionKeys` that
    ///          runs in `upgradeToAndCall` BEFORE this delegatecall.
    ///
    ///      Implementation gating is the factory's responsibility — `upgradeToAndCall`
    ///      rejects any `newImplementation` not in the factory's vetted set. This
    ///      function performs only scheme-specific verification.
    /// @param newImplementation The address of the new implementation being upgraded to.
    /// @param data Packed upgrade payload; verifier at [2272:2336), verifySig at [2336:4480).
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view;

    /// @notice Scheme-compatibility probe run on the new implementation during
    ///         `recoveryUpgrade`. NOT a second authorization factor.
    /// @dev See `verifyUpgrade` for the full semantics. The only difference is the
    ///      payload it decodes from (recoveryUpgrade payload vs. upgradeToAndCall
    ///      payload) and the auth keyset that already gated reaching this point
    ///      (`recoveryKeys` rather than `transactionKeys`).
    /// @param newImplementation The address of the new implementation being upgraded to.
    /// @param data Packed recoveryUpgrade payload; verifier at [2272:2336),
    ///             verifySig at [2336:4480).
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
    ///      At the tail of this flow, the wallet calls back into the factory via
    ///      `updateWalletOwner(oldOwner, newOwner)` so the factory's per-owner
    ///      vaultIds set stays consistent with `owner()`.
    ///      Payload layout: [0:64) currentOwnershipKey, [64:128) newOwnershipKey,
    ///      [128:2272) pqSig, [2272:2304) newOwner, [2304:2368) newDisasterKey,
    ///      [2368:2688) newTransactionKeys[5], [2688:3328) newRecoveryKeys[10].
    /// @param payload Packed ownership-transfer data (3328 bytes).
    function transferOwnership(bytes calldata payload) external payable;

    /// @notice Returns the wallet's classical owner address (Solady Ownable).
    /// @dev Read by the factory's `updateWalletOwner` callback to pin the
    ///      callback to the tail of `transferOwnership(bytes)`. Exposed here
    ///      so the factory does not need to depend on Solady's Ownable types.
    function owner() external view returns (address);

    /// @notice Returns the current execute fee as set by the factory.
    /// @return The execute fee in wei.
    function getExecuteFee() external view returns (uint256);

    /// @notice Returns the address of the QuipFactory that created this wallet.
    /// @return The factory address.
    function quipFactory() external view returns (address payable);

    /// @notice Returns the current `disasterRecoveryKey` — the WOTS+ public
    ///         key that authorizes `saveWallet`. Stored at a fixed slot and
    ///         rotates on use.
    /// @return The disaster recovery Winternitz public key.
    function getDisasterRecoveryKey()
        external
        view
        returns (WOTSPlus.WinternitzAddress memory);

    /// @notice Returns the current `ownershipKey` — the WOTS+ public key
    ///         that authorizes `transferOwnership` /
    ///         `completeOwnershipHandover`. Stored at a fixed slot and
    ///         rotates on use.
    /// @return The ownership Winternitz public key.
    function getOwnershipKey()
        external
        view
        returns (WOTSPlus.WinternitzAddress memory);

    /// @notice Returns the number of keys in the selected keyset.
    /// @param kind The keyset to query.
    /// @return The number of active keys in that keyset.
    function keyCount(
        WOTSPlusCodec.KeyType kind
    ) external view returns (uint256);

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

    /// @notice Returns true if `key` has ever been installed in this wallet —
    ///         in any keyset (transaction / recovery / verification) or either
    ///         single-key slot (`disasterRecoveryKey`, `ownershipKey`).
    /// @dev Monotonic: once true, stays true even after the key has been
    ///      rotated out of its live slot. Off-chain callers should use this
    ///      as the pre-flight check before sending a userOp whose `nextKey`
    ///      will be subject to the contract's `_enforceUnspentKey` guard —
    ///      `isKey(kind, key)` (live-membership) is insufficient because a
    ///      key can be historically burned without being currently live.
    /// @param key The Winternitz public key to query.
    /// @return True if the key has ever been installed in this wallet.
    function isKeySpent(
        WOTSPlus.WinternitzAddress calldata key
    ) external view returns (bool);

    /// @notice Returns every key in the selected keyset in a single read.
    /// @dev Storage-order array; identical semantics to iterating `keyAt`
    ///      from `0` to `keyCount(kind) - 1`. Off-chain callers should
    ///      prefer this over `keyCount`+`keyAt` loops to avoid the
    ///      `1 + N` round-trip pattern.
    /// @param kind The keyset to query.
    /// @return Every active key in the selected keyset.
    function getKeyset(
        WOTSPlusCodec.KeyType kind
    ) external view returns (WOTSPlus.WinternitzAddress[] memory);

    /// @notice Returns every WOTS+ key the wallet currently holds.
    /// @dev Aggregates the two single-slot keys (`disasterRecoveryKey`,
    ///      `ownershipKey`) and the three keysets (`transactionKeys`,
    ///      `recoveryKeys`, `verificationKeys`) into one read. Intended
    ///      for off-chain consumers (SDKs, indexers, recovery UIs) that
    ///      need a full snapshot.
    /// @return The full key state.
    function getAllKeys() external view returns (AllKeys memory);

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
    ///      For `WOTSPlusCodec.KeyType.Transaction`, the extras are appended to
    ///      the active transaction set;
    ///      for `Recovery` / `Verification`, the target set is extended.
    ///      The transaction rotation is committed before the target-set write.
    ///      Payload layout: [0:32) kind, [32:96) currentKey, [96:160) nextKey,
    ///      [160:2304) pqSig, [2304:...) keys (N x 64).
    /// @param payload Packed keyManagement data (>= 2304 bytes).
    function addKeys(bytes calldata payload) external;

    /// @notice Clears the target keyset and installs a fresh batch.
    /// @dev Reverts with `RefreshTransactionForbidden` when
    ///      `kind == WOTSPlusCodec.KeyType.Transaction` —
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

    /// @notice Atomically swaps N keys in/out of the target keyset under one
    ///         WOTS+ signature. The signing keyset may differ from the target,
    ///         enabling cross-keyset authorization (e.g. a recovery key may
    ///         authorize a replacement on the transaction keyset).
    /// @dev Authorization model:
    ///        - `signingKind` ∈ {Transaction, Recovery}. Verification is
    ///          rejected with `InvalidSigningKeyset`.
    ///        - `kind` selects the target keyset (any of the three) whose
    ///          entries are swapped.
    ///        - Six (signingKind × kind) combinations are valid; each has its
    ///          own domain tag in the digest so a signature cannot be lifted
    ///          across signing or target keysets.
    ///      Behavior:
    ///        - The signing keyset rotates `(currentKey → nextKey)` exactly
    ///          once via `_verifyAndRotate`, which doubles as the
    ///          membership integrity check for `signingKind`.
    ///        - The target keyset undergoes `n` ordered `(remove, add)` pairs:
    ///          `target.remove(oldKeys[i])` then `target.add(newKeys[i])` for
    ///          each `i ∈ [0, n)`. Per-iteration remove-then-add keeps the
    ///          set below `MAX_KEYS` at all times (reversing would trip the
    ///          capacity cap since the target sits at `MAX_KEYS` by
    ///          invariant).
    ///        - One signature covers the entire batch; verification is not
    ///          per-iteration.
    ///      Caller obligations when `signingKind == kind`:
    ///        - `currentKey` MUST NOT appear in `oldKeys` (signing rotation
    ///          already removed it; the redundant remove reverts
    ///          `KeyRemovalFailed`).
    ///        - `nextKey` MUST NOT appear in `newKeys` (signing rotation
    ///          already installed and burned it in `isKeySpent`; the
    ///          redundant add reverts `KeyInUse`).
    ///      Payload layout: [0:32) kind, [32:64) signingKind, [64:96) n,
    ///      [96:160) currentKey, [160:224) nextKey, [224:2368) pqSig,
    ///      [2368:2368+n*64) oldKeys, [2368+n*64:2368+2*n*64) newKeys.
    /// @param payload Packed replaceKeys data (2368 + 2*n*64 bytes).
    function replaceKeys(bytes calldata payload) external;

    /// @notice Returns the implementation version of this wallet.
    /// @dev Reads the ERC-1967 implementation slot and queries the factory for
    ///      the index of its codehash in the vetted set.
    /// @return The index in the factory's vetted set, or `type(uint256).max` if not found.
    function version() external view returns (uint256);

    /// @notice Off-chain diagnostic for `isValidSignature`.
    /// @dev EIP-1271 only allows `isValidSignature` to return `0x1626ba7e` or
    ///      `0xffffffff`, collapsing four distinct failure modes
    ///      (bad signature length, ECDSA recovery mismatch, verifier not in
    ///      keyset, WOTS+ verify fails) into a single magic. Integration
    ///      debuggers can call this view via `eth_call` to recover the specific
    ///      reason. Not part of EIP-1271; do not call from on-chain consumers.
    /// @param hash The 32-byte digest the caller signed.
    /// @param signature The 2273-byte ERC-1271 signature payload.
    /// @return Reason code; `Ok` mirrors the magic, anything else mirrors `0xffffffff`.
    function debugIsValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (Erc1271ValidationResult);
}
