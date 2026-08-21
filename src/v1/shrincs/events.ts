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
  type ContractEventName,
  type Hex,
  type Log,
  type ParseEventLogsReturnType,
  type TransactionReceipt,
  parseEventLogs,
} from "viem";

import { shrincsWalletAbi } from "./abi/ShrincsWallet.js";
import { shrincsPaymasterAbi } from "./abi/ShrincsPaymaster.js";
import {
  PaymasterValidationFailure,
  UserOpValidationFailure,
} from "./errors.js";

/// Source for every parser — a full `TransactionReceipt` or a raw `logs` array.
export type LogSource = TransactionReceipt | readonly Log[];

function toLogs(src: LogSource): readonly Log[] {
  return Array.isArray(src) ? src : (src as TransactionReceipt).logs;
}

function walletLogs<
  TEventName extends ContractEventName<typeof shrincsWalletAbi>
>(
  src: LogSource,
  eventName: TEventName
): ParseEventLogsReturnType<typeof shrincsWalletAbi, TEventName, true> {
  return parseEventLogs({
    abi: shrincsWalletAbi,
    logs: [...toLogs(src)],
    eventName,
  });
}

function paymasterLogs<
  TEventName extends ContractEventName<typeof shrincsPaymasterAbi>
>(
  src: LogSource,
  eventName: TEventName
): ParseEventLogsReturnType<typeof shrincsPaymasterAbi, TEventName, true> {
  return parseEventLogs({
    abi: shrincsPaymasterAbi,
    logs: [...toLogs(src)],
    eventName,
  });
}

/*  ── Wallet events (IShrincsWallet) ──────────────────────────────────────  */

export interface WalletInitializedEvent {
  factory: Address;
  owner: Address;
  shrincsPublicKeyCommitment: Hex;
  erc1271StatelessCommitment: Hex;
}

export function parseWalletInitialized(src: LogSource): WalletInitializedEvent[] {
  return walletLogs(src, "WalletInitialized").map((l) => ({
    factory: l.args.factory,
    owner: l.args.owner,
    shrincsPublicKeyCommitment: l.args.shrincsPublicKeyCommitment,
    erc1271StatelessCommitment: l.args.erc1271StatelessCommitment,
  }));
}

export interface StatefulSignatureVerifiedEvent {
  leaf: number;
  keyVersion: bigint;
}

export function parseStatefulSignatureVerified(
  src: LogSource
): StatefulSignatureVerifiedEvent[] {
  return walletLogs(src, "StatefulSignatureVerified").map((l) => ({
    leaf: Number(l.args.leaf),
    keyVersion: l.args.keyVersion,
  }));
}

export interface LeafConsumedOnlyEvent {
  leaf: number;
}

export function parseLeafConsumedOnly(src: LogSource): LeafConsumedOnlyEvent[] {
  return walletLogs(src, "LeafConsumedOnly").map((l) => ({
    leaf: Number(l.args.leaf),
  }));
}

export interface LeafRevokedEvent {
  leaf: number;
  keyVersion: bigint;
}

// `LeafRevoked` and `LeafRevocationSkipped` are emitted by BOTH the wallet and
// the paymaster (each consumes stateful leaves). Decode under both ABIs and
// dedup by (address, logIndex): when the two ABIs share the event signature a
// single physical log decodes under both, so dedup keeps it once; if the ABIs
// ever diverge, each log decodes only under its emitter's ABI, so both sources
// stay covered instead of one silently misparsing under the other's ABI.
function mergeLeafLogs(
  ...groups: readonly {
    address: Address;
    logIndex: number | null;
    args: { leaf: number | bigint; keyVersion: bigint };
  }[][]
): LeafRevokedEvent[] {
  const seen = new Set<string>();
  const out: LeafRevokedEvent[] = [];
  for (const group of groups) {
    for (const l of group) {
      const key = `${l.address}:${l.logIndex}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ leaf: Number(l.args.leaf), keyVersion: l.args.keyVersion });
    }
  }
  return out;
}

export function parseLeafRevoked(src: LogSource): LeafRevokedEvent[] {
  return mergeLeafLogs(
    walletLogs(src, "LeafRevoked"),
    paymasterLogs(src, "LeafRevoked")
  );
}

export interface LeafRevocationSkippedEvent {
  leaf: number;
  keyVersion: bigint;
}

export function parseLeafRevocationSkipped(
  src: LogSource
): LeafRevocationSkippedEvent[] {
  return mergeLeafLogs(
    walletLogs(src, "LeafRevocationSkipped"),
    paymasterLogs(src, "LeafRevocationSkipped")
  );
}

export interface ExecutionSucceededEvent {
  target: Address;
  value: bigint;
  dataHash: Hex;
}

export function parseExecutionSucceeded(src: LogSource): ExecutionSucceededEvent[] {
  return walletLogs(src, "ExecutionSucceeded").map((l) => ({
    target: l.args.target,
    value: l.args.value,
    dataHash: l.args.dataHash,
  }));
}

export interface Erc1271KeySetEvent {
  oldCommitment: Hex;
  newCommitment: Hex;
}

export function parseErc1271KeySet(src: LogSource): Erc1271KeySetEvent[] {
  return walletLogs(src, "Erc1271KeySet").map((l) => ({
    oldCommitment: l.args.oldCommitment,
    newCommitment: l.args.newCommitment,
  }));
}

export interface KeyRotatedEvent {
  previousCommitment: Hex;
  nextCommitment: Hex;
  keyVersion: bigint;
}

export function parseKeyRotated(src: LogSource): KeyRotatedEvent[] {
  return walletLogs(src, "KeyRotated").map((l) => ({
    previousCommitment: l.args.previousCommitment,
    nextCommitment: l.args.nextCommitment,
    keyVersion: l.args.keyVersion,
  }));
}

export interface WalletMigratedEvent {
  shrincsPublicKeyCommitment: Hex;
  keyVersion: bigint;
}

export function parseWalletMigrated(src: LogSource): WalletMigratedEvent[] {
  return walletLogs(src, "WalletMigrated").map((l) => ({
    shrincsPublicKeyCommitment: l.args.shrincsPublicKeyCommitment,
    keyVersion: l.args.keyVersion,
  }));
}

export interface UserOpValidationRejectedEvent {
  reason: UserOpValidationFailure;
}

export function parseUserOpValidationRejected(
  src: LogSource
): UserOpValidationRejectedEvent[] {
  return walletLogs(src, "UserOpValidationRejected").map((l) => ({
    reason: Number(l.args.reason) as UserOpValidationFailure,
  }));
}

/*  ── Paymaster events (IShrincsPaymaster) ────────────────────────────────  */

export interface PaymasterInitializedEvent {
  owner: Address;
}

export function parsePaymasterInitialized(
  src: LogSource
): PaymasterInitializedEvent[] {
  return paymasterLogs(src, "PaymasterInitialized").map((l) => ({
    owner: l.args.owner,
  }));
}

export interface ShrincsVerifierSetEvent {
  previousCommitment: Hex;
  newCommitment: Hex;
  hashSuite: number;
  maxSignatures: number;
  keyVersion: bigint;
}

export function parseShrincsVerifierSet(src: LogSource): ShrincsVerifierSetEvent[] {
  return paymasterLogs(src, "ShrincsVerifierSet").map((l) => ({
    previousCommitment: l.args.previousCommitment,
    newCommitment: l.args.newCommitment,
    hashSuite: Number(l.args.hashSuite),
    maxSignatures: Number(l.args.maxSignatures),
    keyVersion: l.args.keyVersion,
  }));
}

export interface SponsorshipVerifiedEvent {
  wallet: Address;
  leaf: number;
  keyVersion: bigint;
}

export function parseSponsorshipVerified(src: LogSource): SponsorshipVerifiedEvent[] {
  return paymasterLogs(src, "SponsorshipVerified").map((l) => ({
    wallet: l.args.wallet,
    leaf: Number(l.args.leaf),
    keyVersion: l.args.keyVersion,
  }));
}

export interface PaymasterValidationRejectedEvent {
  wallet: Address;
  reason: PaymasterValidationFailure;
}

export function parsePaymasterValidationRejected(
  src: LogSource
): PaymasterValidationRejectedEvent[] {
  return paymasterLogs(src, "PaymasterValidationRejected").map((l) => ({
    wallet: l.args.wallet,
    reason: Number(l.args.reason) as PaymasterValidationFailure,
  }));
}

export interface UserOpSponsoredEvent {
  wallet: Address;
  mode: number;
  actualGasCost: bigint;
  actualUserOpFeePerGas: bigint;
}

export function parseUserOpSponsored(src: LogSource): UserOpSponsoredEvent[] {
  return paymasterLogs(src, "UserOpSponsored").map((l) => ({
    wallet: l.args.wallet,
    mode: Number(l.args.mode),
    actualGasCost: l.args.actualGasCost,
    actualUserOpFeePerGas: l.args.actualUserOpFeePerGas,
  }));
}
