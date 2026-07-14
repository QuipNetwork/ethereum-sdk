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

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec} from "../WOTSPlusCodec.sol";
import {IQuipWallet} from "../../interfaces/IQuipWallet.sol";

/// @title IWOTSPlusImplementation
/// @notice A smart-contract wallet whose operations are authorized by Winternitz
///         one-time signatures, providing post-quantum security for ETH transfers
///         and arbitrary calls.
///         Extends `IQuipWallet` — the factory-facing surface whose natspec
///         states the behavioral vetting contract this implementation upholds.
interface IWOTSPlusImplementation is IQuipWallet {
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
    /// @notice Thrown by `replaceKeys` when `n == 0`.
    error EmptyKeys();
    /// @notice Thrown by `replaceKeys` / `resetKeyset` when the caller-declared
    ///         `signingKind` is `WOTSPlusCodec.KeyType.Verification`.
    ///         Verification keys are not signing-capable; only Transaction or
    ///         Recovery may authorize.
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
    /// @notice Thrown when `migrate` is called outside the `upgradeToAndCall` context.
    error NotUpgrading();
    /// @notice Thrown when the number of transaction keys provided to
    ///         `initialize`/`migrate` is incorrect.
    error IncorrectTransactionKeyAmount();

    /// @notice Thrown when the number of verification keys provided to
    ///         `initialize`/`migrate` is incorrect.
    error IncorrectVerificationKeyAmount();

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
    /// @dev The three keyset arrays are summarized as `keccak256(abi.encode(arr))`
    ///      hashes rather than emitted in full — off-chain indexers recompute
    ///      from the init payload (available via the wallet-creation calldata).
    /// @param factory The QuipFactory that created this wallet.
    /// @param owner The classical owner address.
    /// @param transactionKeysHash `keccak256(abi.encode(transactionKeys[10]))`.
    /// @param recoveryKeysHash `keccak256(abi.encode(recoveryKeys[10]))`.
    /// @param verificationKeysHash `keccak256(abi.encode(verificationKeys[10]))`.
    event WalletInitialized(
        address indexed factory,
        address indexed owner,
        bytes32 indexed transactionKeysHash,
        bytes32 recoveryKeysHash,
        bytes32 verificationKeysHash
    );

    /// @notice Emitted when the wallet is rescued via the disaster recovery key.
    /// @dev `saveWallet` wholesale-resets the three keysets to the installed
    ///      always-10 batches; full arrays are summarized as hashes to keep
    ///      the event payload bounded.
    /// @param oldDisasterRecoveryKey The consumed disaster recovery key.
    /// @param newDisasterRecoveryKey The installed replacement disaster recovery key.
    /// @param newTransactionKeysHash `keccak256(abi.encode(newTransactionKeys[10]))`.
    /// @param newRecoveryKeysHash `keccak256(abi.encode(newRecoveryKeys[10]))`.
    /// @param newVerificationKeysHash `keccak256(abi.encode(newVerificationKeys[10]))`.
    event WalletSaved(
        WOTSPlus.WinternitzAddress oldDisasterRecoveryKey,
        WOTSPlus.WinternitzAddress newDisasterRecoveryKey,
        bytes32 indexed newTransactionKeysHash,
        bytes32 newRecoveryKeysHash,
        bytes32 newVerificationKeysHash
    );

    /// @notice Emitted when ownership is transferred (or handed over) and the PQ state is
    ///         fully re-initialized for the incoming owner.
    /// @dev `transferOwnership` wholesale-resets the three keysets to the installed
    ///      always-10 batches; full arrays are summarized as hashes to keep the event
    ///      payload bounded.
    /// @param oldOwnershipKey The consumed ownership key.
    /// @param newOwnershipKey The installed replacement ownership key.
    /// @param newOwner The classical address that now owns the wallet.
    /// @param newDisasterRecoveryKey The installed replacement disaster recovery key.
    /// @param newTransactionKeysHash `keccak256(abi.encode(newTransactionKeys[10]))`.
    /// @param newRecoveryKeysHash `keccak256(abi.encode(newRecoveryKeys[10]))`.
    /// @param newVerificationKeysHash `keccak256(abi.encode(newVerificationKeys[10]))`.
    event OwnershipReinitialized(
        WOTSPlus.WinternitzAddress oldOwnershipKey,
        WOTSPlus.WinternitzAddress newOwnershipKey,
        address indexed newOwner,
        WOTSPlus.WinternitzAddress newDisasterRecoveryKey,
        bytes32 indexed newTransactionKeysHash,
        bytes32 newRecoveryKeysHash,
        bytes32 newVerificationKeysHash
    );

    /// @notice Emitted when PQ state is migrated during an upgrade.
    /// @dev The three keysets are reinstalled from the migrator payload.
    ///      Full arrays are not emitted — a hash is the cheapest useful
    ///      commitment, and off-chain indexers can recompute from the
    ///      migrator payload via calldata.
    /// @param transactionKeysHash `keccak256(abi.encode(transactionKeys[10]))`.
    /// @param recoveryKeysHash `keccak256(abi.encode(recoveryKeys[10]))`.
    /// @param verificationKeysHash `keccak256(abi.encode(verificationKeys[10]))`.
    event WalletMigrated(
        bytes32 indexed transactionKeysHash,
        bytes32 recoveryKeysHash,
        bytes32 verificationKeysHash
    );

    /// @notice Emitted when a recovery key authorizes an emergency implementation upgrade.
    /// @param newImplementation The new implementation address.
    /// @param recoveryKey The recovery key that authorized the upgrade.
    event RecoveryUpgrade(
        address indexed newImplementation,
        WOTSPlus.WinternitzAddress recoveryKey
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

    /// @notice Emitted when a keyset is wholesale-reset via `resetKeyset`.
    /// @dev Emitted after the signing-keyset rotation and the target-set
    ///      clear+install have committed. `kind` and `signingKind` together
    ///      identify which of the 6 (signingKind × targetKind) variants ran.
    /// @param kind The target keyset that was cleared and reinstalled.
    /// @param signingKind The keyset that authorized the reset (Tx or Recovery).
    /// @param currentKey The consumed (rotated-out) key from `signingKind` set.
    /// @param nextKey The replacement key installed in `signingKind` set.
    /// @param newKeys The 10 keys installed as the entire new target keyset.
    event KeysetReset(
        WOTSPlusCodec.KeyType indexed kind,
        WOTSPlusCodec.KeyType indexed signingKind,
        WOTSPlus.WinternitzAddress currentKey,
        WOTSPlus.WinternitzAddress nextKey,
        WOTSPlus.WinternitzAddress[10] newKeys
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
    ///      [4480] shouldMigrate, [4481:6529) migratorPayload (new init layout, 2048 bytes).
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
    ///         ownership key, transaction keys, recovery keys, and verification keys.
    /// @dev Can only be called once by the FACTORY. Uses Solady's `initializer` modifier.
    ///      Payload layout: [0:64) disasterRecoveryKey, [64:128) ownershipKey,
    ///      [128:768) transactionKeys (10 x 64), [768:1408) recoveryKeys (10 x 64),
    ///      [1408:2048) verificationKeys (10 x 64).
    /// @param newOwner The classical owner address.
    /// @param payload Packed init data (2048 bytes).
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) external override;

    /// @notice Re-initializes the PQ state (disaster recovery key + ownership key +
    ///         transaction, recovery, and verification keysets) during an upgrade.
    /// @dev Only callable by the classical owner. Called via delegatecall from upgradeToAndCall
    ///      so that it executes against proxy storage.
    ///      Payload layout matches `initialize` (2048 bytes).
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
    ///      transaction keyset, recovery keyset, and verification keyset that the incoming
    ///      owner alone controls. All three keysets are wholesale-replaced to the always-10
    ///      invariant. The existing `ownershipKey` rotates to the supplied replacement
    ///      (one-time-use).
    ///      At the tail of this flow, the wallet calls back into the factory via
    ///      `updateWalletOwner(oldOwner, newOwner)` so the factory's per-owner
    ///      vaultIds set stays consistent with `owner()`.
    ///      Payload layout: [0:64) currentOwnershipKey, [64:128) newOwnershipKey,
    ///      [128:2272) pqSig, [2272:2304) newOwner, [2304:2368) newDisasterKey,
    ///      [2368:3008) newTransactionKeys[10], [3008:3648) newRecoveryKeys[10],
    ///      [3648:4288) newVerificationKeys[10].
    /// @param payload Packed ownership-transfer data (4288 bytes).
    function transferOwnership(bytes calldata payload) external payable;

    /// @notice Returns the wallet's classical owner address (Solady Ownable).
    /// @dev Read by the factory's `updateWalletOwner` callback to pin the
    ///      callback to the tail of `transferOwnership(bytes)`. Exposed here
    ///      so the factory does not need to depend on Solady's Ownable types.
    function owner() external view override returns (address);

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

    /// @notice Last-resort rescue: resets `transactionKeys`, `recoveryKeys`, and
    ///         `verificationKeys` using the wallet's disaster recovery key. Leaves
    ///         `owner()` and `ownershipKey` intact.
    /// @dev Authorized solely by a WOTS+ signature from the stored disaster recovery key.
    ///      The key rotates on use — the payload carries a `newDisasterRecoveryKey` that
    ///      replaces the consumed one. No `onlyOwner` gate: if the classical owner is also
    ///      compromised, this path must still be reachable.
    ///
    ///      Payload layout: [0:64) currentDisasterKey, [64:128) newDisasterKey,
    ///      [128:2272) pqSig, [2272:2912) newTransactionKeys[10],
    ///      [2912:3552) newRecoveryKeys[10], [3552:4192) newVerificationKeys[10].
    /// @param payload Packed saveWallet data (4192 bytes).
    function saveWallet(bytes calldata payload) external;

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

    /// @notice Wholesale clears the target keyset and reinstalls 10 fresh keys
    ///         under one WOTS+ signature. The signing keyset may differ from
    ///         the target, enabling cross-keyset authorization.
    /// @dev Authorization model:
    ///        - `signingKind` ∈ {Transaction, Recovery}. Verification is
    ///          rejected with `InvalidSigningKeyset`.
    ///        - `kind` selects the target keyset (any of the three) that is
    ///          cleared and reinstalled.
    ///        - Six (signingKind × kind) combinations are valid; each has its
    ///          own domain tag in the digest so a signature cannot be lifted
    ///          across signing or target keysets.
    ///      Behavior:
    ///        - The signing keyset rotates `(currentKey → nextKey)` exactly
    ///          once via `_verifyAndRotate`, which doubles as the membership
    ///          integrity check for `signingKind`.
    ///        - The target keyset is `_clearKeys`'d (single-pass remove),
    ///          then 10 `_safeAddKey` calls install `newKeys` in order. Each
    ///          add is guarded by the global `isKeySpent` index, so any
    ///          historically-installed key (including `currentKey` and
    ///          `nextKey`) is rejected with `KeyInUse`.
    ///        - One signature covers the whole reset; verification is not
    ///          per-key.
    ///      Same-keyset auth (`signingKind == kind`) sequencing:
    ///        - Rotate adds `nextKey` to the target; clear wipes it again;
    ///          install loop rebuilds the target from `newKeys`. The caller
    ///          MUST NOT include `currentKey` or `nextKey` in `newKeys` — the
    ///          burn index will reject either with `KeyInUse`.
    ///      Resets the target to exactly `MAX_KEYS` entries regardless of its
    ///      starting size (works even when the verification keyset is empty
    ///      before the always-10 invariant is established).
    ///      Payload layout: [0:32) kind, [32:64) signingKind,
    ///      [64:128) currentKey, [128:192) nextKey, [192:2336) pqSig,
    ///      [2336:2976) newKeys[10].
    /// @param payload Packed resetKeyset data (2976 bytes).
    function resetKeyset(bytes calldata payload) external;

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

    /// @notice Returns the EIP-712-wrapped hash that the ECDSA half of
    ///         `isValidSignature` recovers against. Useful for SDK
    ///         integrators that need to compute the signing target locally —
    ///         the returned bytes32 is what the classical `owner()` key must
    ///         produce a secp256k1 signature over.
    /// @dev    The wrap binds the ECDSA signature to this wallet's EIP-712
    ///         domain (`name="QuipWallet"`, `version="1"`, `chainId`,
    ///         `verifyingContract=address(this)`), preventing replay across
    ///         wallets that share the same classical `owner()`.
    /// @param  hash The raw 32-byte hash a protocol (Permit2, Seaport, …)
    ///         hands to `isValidSignature`.
    /// @return The EIP-712 typed-data hash:
    ///         `keccak256(0x1901 || domainSeparator ||
    ///         keccak256(abi.encode(QUIP_SIGNED_HASH_TYPEHASH, hash)))`,
    ///         where `QUIP_SIGNED_HASH_TYPEHASH ==
    ///         keccak256("QuipSignedHash(bytes32 hash)")`.
    function quipSignedHashEcdsaTarget(
        bytes32 hash
    ) external view returns (bytes32);
}
