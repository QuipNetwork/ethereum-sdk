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

function walletLogs(src: LogSource, eventName: string) {
  return parseEventLogs({
    abi: shrincsWalletAbi,
    logs: toLogs(src) as Log[],
    eventName,
  } as Parameters<typeof parseEventLogs>[0]);
}

function paymasterLogs(src: LogSource, eventName: string) {
  return parseEventLogs({
    abi: shrincsPaymasterAbi,
    logs: toLogs(src) as Log[],
    eventName,
  } as Parameters<typeof parseEventLogs>[0]);
}

/*  ── Wallet events (IShrincsWallet) ──────────────────────────────────────  */

export interface WalletInitializedEvent {
  factory: Address;
  owner: Address;
  shrincsPublicKeyCommitment: Hex;
  erc1271StatelessCommitment: Hex;
}

export function parseWalletInitialized(src: LogSource): WalletInitializedEvent[] {
  return walletLogs(src, "WalletInitialized").map((l: any) => ({
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
  return walletLogs(src, "StatefulSignatureVerified").map((l: any) => ({
    leaf: Number(l.args.leaf),
    keyVersion: l.args.keyVersion,
  }));
}

export interface LeafConsumedOnlyEvent {
  leaf: number;
}

export function parseLeafConsumedOnly(src: LogSource): LeafConsumedOnlyEvent[] {
  return walletLogs(src, "LeafConsumedOnly").map((l: any) => ({
    leaf: Number(l.args.leaf),
  }));
}

export interface ExecutionSucceededEvent {
  target: Address;
  value: bigint;
  dataHash: Hex;
}

export function parseExecutionSucceeded(src: LogSource): ExecutionSucceededEvent[] {
  return walletLogs(src, "ExecutionSucceeded").map((l: any) => ({
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
  return walletLogs(src, "Erc1271KeySet").map((l: any) => ({
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
  return walletLogs(src, "KeyRotated").map((l: any) => ({
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
  return walletLogs(src, "WalletMigrated").map((l: any) => ({
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
  return walletLogs(src, "UserOpValidationRejected").map((l: any) => ({
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
  return paymasterLogs(src, "PaymasterInitialized").map((l: any) => ({
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
  return paymasterLogs(src, "ShrincsVerifierSet").map((l: any) => ({
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
  return paymasterLogs(src, "SponsorshipVerified").map((l: any) => ({
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
  return paymasterLogs(src, "PaymasterValidationRejected").map((l: any) => ({
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
  return paymasterLogs(src, "UserOpSponsored").map((l: any) => ({
    wallet: l.args.wallet,
    mode: Number(l.args.mode),
    actualGasCost: l.args.actualGasCost,
    actualUserOpFeePerGas: l.args.actualUserOpFeePerGas,
  }));
}
