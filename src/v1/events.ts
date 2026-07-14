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
import {
  type Address,
  type Hex,
  type Log,
  type TransactionReceipt,
  parseEventLogs,
} from "viem";

import { quipFactoryAbi } from "./abi/QuipFactory.js";
import { quipPaymasterAbi } from "./abi/QuipPaymaster.js";
import { wotsPlusImplementationAbi } from "./abi/WOTSPlusImplementation.js";
import {
  PaymasterValidationFailure,
  UserOpValidationFailure,
} from "./errors.js";
import { KeyType, type WinternitzAddress } from "./wotsCodec.js";

/// Source for every parser — either a full `TransactionReceipt` or a raw
/// `logs` array. `Log[]` covers `eth_getLogs` / `watchContractEvent`
/// callbacks where no receipt exists.
export type LogSource = TransactionReceipt | readonly Log[];

function toLogs(src: LogSource): readonly Log[] {
  return Array.isArray(src) ? src : (src as TransactionReceipt).logs;
}

/*  ───────────────────────────────────────────────────────────────────  *
 *  Wallet events (IWOTSPlusImplementation)                                          *
 *  ───────────────────────────────────────────────────────────────────  */

export interface KeyRotatedEvent {
  oldKey: WinternitzAddress;
  newKey: WinternitzAddress;
}

export function parseKeyRotated(src: LogSource): KeyRotatedEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "KeyRotated",
  }).map((l) => ({
    oldKey: l.args.oldKey,
    newKey: l.args.newKey,
  }));
}

export interface ExecutionSucceededEvent {
  target: Address;
  value: bigint;
  dataHash: Hex;
}

export function parseExecutionSucceeded(
  src: LogSource
): ExecutionSucceededEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "ExecutionSucceeded",
  }).map((l) => ({
    target: l.args.target,
    value: l.args.value,
    dataHash: l.args.dataHash,
  }));
}

export interface KeyRotationOnlyEvent {
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
}

export function parseKeyRotationOnly(
  src: LogSource
): KeyRotationOnlyEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "KeyRotationOnly",
  }).map((l) => ({
    currentKey: l.args.currentKey,
    nextKey: l.args.nextKey,
  }));
}

export interface WalletInitializedEvent {
  factory: Address;
  owner: Address;
  transactionKeysHash: Hex;
  recoveryKeysHash: Hex;
  verificationKeysHash: Hex;
}

export function parseWalletInitialized(
  src: LogSource
): WalletInitializedEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "WalletInitialized",
  }).map((l) => ({
    factory: l.args.factory,
    owner: l.args.owner,
    transactionKeysHash: l.args.transactionKeysHash,
    recoveryKeysHash: l.args.recoveryKeysHash,
    verificationKeysHash: l.args.verificationKeysHash,
  }));
}

export interface WalletSavedEvent {
  oldDisasterRecoveryKey: WinternitzAddress;
  newDisasterRecoveryKey: WinternitzAddress;
  newTransactionKeysHash: Hex;
  newRecoveryKeysHash: Hex;
  newVerificationKeysHash: Hex;
}

export function parseWalletSaved(src: LogSource): WalletSavedEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "WalletSaved",
  }).map((l) => ({
    oldDisasterRecoveryKey: l.args.oldDisasterRecoveryKey,
    newDisasterRecoveryKey: l.args.newDisasterRecoveryKey,
    newTransactionKeysHash: l.args.newTransactionKeysHash,
    newRecoveryKeysHash: l.args.newRecoveryKeysHash,
    newVerificationKeysHash: l.args.newVerificationKeysHash,
  }));
}

export interface OwnershipReinitializedEvent {
  oldOwnershipKey: WinternitzAddress;
  newOwnershipKey: WinternitzAddress;
  newOwner: Address;
  newDisasterRecoveryKey: WinternitzAddress;
  newTransactionKeysHash: Hex;
  newRecoveryKeysHash: Hex;
  newVerificationKeysHash: Hex;
}

export function parseOwnershipReinitialized(
  src: LogSource
): OwnershipReinitializedEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "OwnershipReinitialized",
  }).map((l) => ({
    oldOwnershipKey: l.args.oldOwnershipKey,
    newOwnershipKey: l.args.newOwnershipKey,
    newOwner: l.args.newOwner,
    newDisasterRecoveryKey: l.args.newDisasterRecoveryKey,
    newTransactionKeysHash: l.args.newTransactionKeysHash,
    newRecoveryKeysHash: l.args.newRecoveryKeysHash,
    newVerificationKeysHash: l.args.newVerificationKeysHash,
  }));
}

/// `KeysReplaced` is emitted when an N-for-N swap via `replaceKeys`
/// succeeds. `kind` identifies the target keyset; `signingKind` says
/// which set authorized the swap (Tx or Recovery).
export interface KeysReplacedEvent {
  kind: KeyType;
  signingKind: KeyType;
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  oldKeys: readonly WinternitzAddress[];
  newKeys: readonly WinternitzAddress[];
}

export function parseKeysReplaced(src: LogSource): KeysReplacedEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "KeysReplaced",
  }).map((l) => ({
    kind: Number(l.args.kind) as KeyType,
    signingKind: Number(l.args.signingKind) as KeyType,
    currentKey: l.args.currentKey,
    nextKey: l.args.nextKey,
    oldKeys: l.args.oldKeys,
    newKeys: l.args.newKeys,
  }));
}

/// `KeysetReset` is emitted when a keyset is wholesale-reset via
/// `resetKeyset`. `kind` identifies the target keyset; `signingKind`
/// says which set authorized the reset (Tx or Recovery).
export interface KeysetResetEvent {
  kind: KeyType;
  signingKind: KeyType;
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  newKeys: readonly WinternitzAddress[];
}

export function parseKeysetReset(src: LogSource): KeysetResetEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "KeysetReset",
  }).map((l) => ({
    kind: Number(l.args.kind) as KeyType,
    signingKind: Number(l.args.signingKind) as KeyType,
    currentKey: l.args.currentKey,
    nextKey: l.args.nextKey,
    newKeys: l.args.newKeys,
  }));
}

export interface WalletMigratedEvent {
  transactionKeysHash: Hex;
  recoveryKeysHash: Hex;
  verificationKeysHash: Hex;
}

export function parseWalletMigrated(src: LogSource): WalletMigratedEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "WalletMigrated",
  }).map((l) => ({
    transactionKeysHash: l.args.transactionKeysHash,
    recoveryKeysHash: l.args.recoveryKeysHash,
    verificationKeysHash: l.args.verificationKeysHash,
  }));
}

export interface RecoveryUpgradeEvent {
  newImplementation: Address;
  recoveryKey: WinternitzAddress;
}

export function parseRecoveryUpgrade(
  src: LogSource
): RecoveryUpgradeEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "RecoveryUpgrade",
  }).map((l) => ({
    newImplementation: l.args.newImplementation,
    recoveryKey: l.args.recoveryKey,
  }));
}

export interface UserOpValidationRejectedEvent {
  reason: UserOpValidationFailure;
}

export function parseUserOpValidationRejected(
  src: LogSource
): UserOpValidationRejectedEvent[] {
  return parseEventLogs({
    abi: wotsPlusImplementationAbi,
    logs: toLogs(src) as Log[],
    eventName: "UserOpValidationRejected",
  }).map((l) => ({
    reason: Number(l.args.reason) as UserOpValidationFailure,
  }));
}

/*  ───────────────────────────────────────────────────────────────────  *
 *  Factory events (IQuipFactory)                                        *
 *  ───────────────────────────────────────────────────────────────────  */

export interface QuipCreatedEvent {
  amount: bigint;
  when: bigint;
  vaultId: Hex;
  creator: Address;
  /// The vetted implementation the proxy was deployed with — identifies the
  /// wallet family/version. Key material is not echoed by the factory (the
  /// init payload is opaque to it); read each family's own WalletInitialized
  /// event or on-chain wallet state instead.
  implementation: Address;
  quip: Address;
}

export function parseQuipCreated(src: LogSource): QuipCreatedEvent[] {
  return parseEventLogs({
    abi: quipFactoryAbi,
    logs: toLogs(src) as Log[],
    eventName: "QuipCreated",
  }).map((l) => ({
    amount: l.args.amount,
    when: l.args.when,
    vaultId: l.args.vaultId,
    creator: l.args.creator,
    implementation: l.args.implementation,
    quip: l.args.quip,
  }));
}

export interface CreationFeeUpdatedEvent {
  oldFee: bigint;
  newFee: bigint;
}

export function parseCreationFeeUpdated(
  src: LogSource
): CreationFeeUpdatedEvent[] {
  return parseEventLogs({
    abi: quipFactoryAbi,
    logs: toLogs(src) as Log[],
    eventName: "CreationFeeUpdated",
  }).map((l) => ({
    oldFee: l.args.oldFee,
    newFee: l.args.newFee,
  }));
}

export interface ExecuteFeeUpdatedEvent {
  oldFee: bigint;
  newFee: bigint;
}

export function parseExecuteFeeUpdated(
  src: LogSource
): ExecuteFeeUpdatedEvent[] {
  return parseEventLogs({
    abi: quipFactoryAbi,
    logs: toLogs(src) as Log[],
    eventName: "ExecuteFeeUpdated",
  }).map((l) => ({
    oldFee: l.args.oldFee,
    newFee: l.args.newFee,
  }));
}

export interface ImplementationVettedEvent {
  impl: Address;
  codehash: Hex;
}

export function parseImplementationVetted(
  src: LogSource
): ImplementationVettedEvent[] {
  return parseEventLogs({
    abi: quipFactoryAbi,
    logs: toLogs(src) as Log[],
    eventName: "ImplementationVetted",
  }).map((l) => ({
    impl: l.args.impl,
    codehash: l.args.codehash,
  }));
}

export interface ImplementationSunsetEvent {
  impl: Address;
  codehash: Hex;
}

export function parseImplementationSunset(
  src: LogSource
): ImplementationSunsetEvent[] {
  return parseEventLogs({
    abi: quipFactoryAbi,
    logs: toLogs(src) as Log[],
    eventName: "ImplementationSunset",
  }).map((l) => ({
    impl: l.args.impl,
    codehash: l.args.codehash,
  }));
}

export interface ImplementationUndeprecatedEvent {
  impl: Address;
  codehash: Hex;
}

export function parseImplementationUndeprecated(
  src: LogSource
): ImplementationUndeprecatedEvent[] {
  return parseEventLogs({
    abi: quipFactoryAbi,
    logs: toLogs(src) as Log[],
    eventName: "ImplementationUndeprecated",
  }).map((l) => ({
    impl: l.args.impl,
    codehash: l.args.codehash,
  }));
}

export interface WithdrawnEvent {
  to: Address;
  amount: bigint;
}

/// `Withdrawn` is emitted by the factory when the owner pulls accumulated
/// fees. (The paymaster's deposit-side withdrawals route through the
/// EntryPoint and surface as `Withdrawn` on the EntryPoint, not on the
/// paymaster itself.)
export function parseWithdrawn(src: LogSource): WithdrawnEvent[] {
  return parseEventLogs({
    abi: quipFactoryAbi,
    logs: toLogs(src) as Log[],
    eventName: "Withdrawn",
  }).map((l) => ({
    to: l.args.to,
    amount: l.args.amount,
  }));
}

/*  ───────────────────────────────────────────────────────────────────  *
 *  Paymaster events (IQuipPaymaster)                                    *
 *  ───────────────────────────────────────────────────────────────────  */

export interface PaymasterInitializedEvent {
  owner: Address;
}

export function parsePaymasterInitialized(
  src: LogSource
): PaymasterInitializedEvent[] {
  return parseEventLogs({
    abi: quipPaymasterAbi,
    logs: toLogs(src) as Log[],
    eventName: "PaymasterInitialized",
  }).map((l) => ({
    owner: l.args.owner,
  }));
}

export interface PqVerifierSetEvent {
  wallet: Address;
  oldVerifier: WinternitzAddress;
  newVerifier: WinternitzAddress;
}

export function parsePqVerifierSet(src: LogSource): PqVerifierSetEvent[] {
  return parseEventLogs({
    abi: quipPaymasterAbi,
    logs: toLogs(src) as Log[],
    eventName: "PqVerifierSet",
  }).map((l) => ({
    wallet: l.args.wallet,
    oldVerifier: l.args.oldVerifier,
    newVerifier: l.args.newVerifier,
  }));
}

export interface PqVerifierRemovedEvent {
  wallet: Address;
}

export function parsePqVerifierRemoved(
  src: LogSource
): PqVerifierRemovedEvent[] {
  return parseEventLogs({
    abi: quipPaymasterAbi,
    logs: toLogs(src) as Log[],
    eventName: "PqVerifierRemoved",
  }).map((l) => ({
    wallet: l.args.wallet,
  }));
}

export interface PqVerifierRotatedEvent {
  wallet: Address;
  currentVerifier: WinternitzAddress;
  nextVerifier: WinternitzAddress;
}

export function parsePqVerifierRotated(
  src: LogSource
): PqVerifierRotatedEvent[] {
  return parseEventLogs({
    abi: quipPaymasterAbi,
    logs: toLogs(src) as Log[],
    eventName: "PqVerifierRotated",
  }).map((l) => ({
    wallet: l.args.wallet,
    currentVerifier: l.args.currentVerifier,
    nextVerifier: l.args.nextVerifier,
  }));
}

export interface PaymasterValidationRejectedEvent {
  wallet: Address;
  reason: PaymasterValidationFailure;
}

export function parsePaymasterValidationRejected(
  src: LogSource
): PaymasterValidationRejectedEvent[] {
  return parseEventLogs({
    abi: quipPaymasterAbi,
    logs: toLogs(src) as Log[],
    eventName: "PaymasterValidationRejected",
  }).map((l) => ({
    wallet: l.args.wallet,
    reason: Number(l.args.reason) as PaymasterValidationFailure,
  }));
}

export interface UserOpSponsoredEvent {
  wallet: Address;
  /// EntryPoint v0.7 `PostOpMode` enum (0 = opSucceeded, 1 = opReverted, 2 = postOpReverted).
  mode: number;
  actualGasCost: bigint;
  actualUserOpFeePerGas: bigint;
}

export function parseUserOpSponsored(
  src: LogSource
): UserOpSponsoredEvent[] {
  return parseEventLogs({
    abi: quipPaymasterAbi,
    logs: toLogs(src) as Log[],
    eventName: "UserOpSponsored",
  }).map((l) => ({
    wallet: l.args.wallet,
    mode: Number(l.args.mode),
    actualGasCost: l.args.actualGasCost,
    actualUserOpFeePerGas: l.args.actualUserOpFeePerGas,
  }));
}

/*  ───────────────────────────────────────────────────────────────────  *
 *  Wallet-receipt aggregator                                            *
 *  ───────────────────────────────────────────────────────────────────  */

/// Discriminated union over what a wallet `execute(bytes)` receipt can
/// represent at the contract level. Two mutually exclusive shapes:
///
///   - 'executed'      — inner call succeeded. Carries the target / value /
///                       calldata-hash and the wallet-side rotation. The
///                       `KeyRotated` pair is present whenever the wallet
///                       consumed a transaction key (i.e. every `execute`).
///   - 'rotation-only' — `execute(zeroAddr, 0, "0x")` — the wallet rotates
///                       its head transaction key without making an inner
///                       call. Distinguishable from a real transfer-to-zero
///                       by the absence of `ExecutionSucceeded`.
///
/// Inner-call failure reverts the whole transaction (no event is emitted,
/// no key rotates) — there is no 'reverted' shape because the receipt
/// itself indicates the failure.
///
/// A receipt may also carry no wallet-execute event at all (e.g. a
/// key-management write like `replaceKeys` produces `KeysReplaced` +
/// `KeyRotated` but no execution event). In that case `parseWalletReceipt`
/// returns `null` — the caller is expected to use a more specific parser
/// (`parseKeysReplaced`, `parseKeysetReset`, etc.) for those flows.
export type WalletTxResult =
  | {
      kind: "executed";
      target: Address;
      value: bigint;
      dataHash: Hex;
      rotation: KeyRotatedEvent;
    }
  | {
      kind: "rotation-only";
      currentKey: WinternitzAddress;
      nextKey: WinternitzAddress;
    };

/// Aggregate a wallet `execute(bytes)` receipt into a `WalletTxResult`.
/// Returns `null` if no execution / rotation-only event is present (e.g.
/// the receipt is from a key-management write).
export function parseWalletReceipt(src: LogSource): WalletTxResult | null {
  const logs = toLogs(src);

  const successes = parseExecutionSucceeded(logs);
  const rotationsOnly = parseKeyRotationOnly(logs);

  if (rotationsOnly.length > 0) {
    const r = rotationsOnly[0];
    return {
      kind: "rotation-only",
      currentKey: r.currentKey,
      nextKey: r.nextKey,
    };
  }

  if (successes.length > 0) {
    const rotations = parseKeyRotated(logs);
    if (rotations.length === 0) {
      // Defensive: every execute path emits exactly one KeyRotated. If the
      // receipt is malformed, treat it as no result.
      return null;
    }
    const s = successes[0];
    return {
      kind: "executed",
      target: s.target,
      value: s.value,
      dataHash: s.dataHash,
      rotation: rotations[0],
    };
  }

  return null;
}
