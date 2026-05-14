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
  type Account,
  type Address,
  type PublicClient,
} from "viem";

import {
  BalanceTooLowError,
  GasEstimationError,
  QuipError,
} from "./errors.js";
import { decodeContractError } from "./internal/decodeError.js";

/// Default safety margin applied on top of `eth_estimateGas` results.
/// 20% mirrors the existing `executeWithWinternitz` heuristic.
export const DEFAULT_GAS_BUFFER_PERCENT = 20;

/// Hard cap on the buffer to keep callers from accidentally requesting
/// outrageously high gas via misconfiguration.
export const MAX_GAS_BUFFER_PERCENT = 100;

/// Per-call transaction-shaping options accepted by every write method on
/// the SDK. All fields are optional; unset values fall through to viem's
/// defaults (eth_gasPrice / eth_feeHistory / chain nonce manager).
export interface TxOptions {
  /// Explicit gas limit. When set, skips the `estimateContractGas` call and
  /// the buffer step entirely.
  gas?: bigint;
  /// Multiplier applied to the gas estimate: `gas = estimate * (1 + buf/100)`.
  /// Default `DEFAULT_GAS_BUFFER_PERCENT` (20). Capped at
  /// `MAX_GAS_BUFFER_PERCENT` (100). Negative or non-finite values clamp to 0.
  gasBufferPercent?: number;
  /// EIP-1559 ceiling. Mutually exclusive with `gasPrice`.
  maxFeePerGas?: bigint;
  /// EIP-1559 tip. Mutually exclusive with `gasPrice`.
  maxPriorityFeePerGas?: bigint;
  /// Legacy (pre-1559) gas price. Use on chains that don't support 1559
  /// (e.g. some L2 testnets, MIDL).
  gasPrice?: bigint;
  /// Pin the nonce. Default: viem fetches `eth_getTransactionCount`.
  nonce?: number;
  /// Skip balance preflight (`BalanceTooLowError`). Use when the call's
  /// `value` is funded by a paymaster or when balance has already been
  /// verified externally.
  skipPreflightChecks?: boolean;
}

/// Subset of `TxOptions` that maps to viem fee fields. We forward only
/// the fields the user explicitly set so viem's auto-pricing keeps working
/// for the rest.
export interface FeeOverrides {
  maxFeePerGas?: bigint;
  maxPriorityFeePerGas?: bigint;
  gasPrice?: bigint;
}

/// Output of `prepareTx`: ready-to-spread fields for `writeContract`.
export interface PreparedTx {
  gas: bigint;
  fees: FeeOverrides;
  nonce?: number;
}

/// Apply the configured buffer to a gas estimate.
/// `(estimate * (100 + pct)) / 100`, with `pct` clamped to `[0, MAX]`.
export function applyGasBuffer(estimate: bigint, opts?: TxOptions): bigint {
  let pct = opts?.gasBufferPercent ?? DEFAULT_GAS_BUFFER_PERCENT;
  if (!Number.isFinite(pct) || pct < 0) pct = 0;
  if (pct > MAX_GAS_BUFFER_PERCENT) pct = MAX_GAS_BUFFER_PERCENT;
  // Floor-truncates the input to integer percent before BigInt math.
  return (estimate * (100n + BigInt(Math.floor(pct)))) / 100n;
}

/// Forward only the fee fields the caller explicitly set, so viem's
/// auto-pricing keeps filling in the rest.
export function resolveFeeOptions(opts?: TxOptions): FeeOverrides {
  const out: FeeOverrides = {};
  if (opts?.gasPrice !== undefined) out.gasPrice = opts.gasPrice;
  if (opts?.maxFeePerGas !== undefined) out.maxFeePerGas = opts.maxFeePerGas;
  if (opts?.maxPriorityFeePerGas !== undefined)
    out.maxPriorityFeePerGas = opts.maxPriorityFeePerGas;
  return out;
}

/// Throw `BalanceTooLowError` if the account's balance is below `required`.
/// No-op when `required` is 0 or negative.
export async function preflightBalanceCheck(
  publicClient: PublicClient,
  account: Address,
  required: bigint
): Promise<void> {
  if (required <= 0n) return;
  const balance = await publicClient.getBalance({ address: account });
  if (balance < required) {
    throw new BalanceTooLowError(required, balance);
  }
}

/// Parameters accepted by every viem `estimateContractGas` call that this SDK
/// makes. Matches the structural shape viem expects.
export interface ContractCallParams {
  address: Address;
  abi: readonly unknown[];
  functionName: string;
  args?: readonly unknown[];
  value?: bigint;
  account: Account | Address;
}

export interface PrepareTxParams {
  publicClient: PublicClient;
  contractParams: ContractCallParams;
  /// Total ETH the caller will pay (`msg.value` + protocol fees combined).
  /// Used by `preflightBalanceCheck`. Pass `0n` for value-less calls.
  totalValue: bigint;
  opts?: TxOptions;
}

/// Run pre-flight balance + gas estimation in the order each failure mode
/// wants to surface, with distinct typed errors per stage:
///
///   1. `BalanceTooLowError` — account can't cover `totalValue`.
///   2. Decoded `QuipError` — `estimateContractGas` rejected with a
///      recognized contract revert. `estimateContractGas` runs the call
///      via `eth_call` semantics on the node, so reverts surface here with
///      the same fidelity the old `simulateContract` stage provided.
///   3. `GasEstimationError` — `estimateContractGas` rejected for a
///      non-contract reason (network, invalid params, …).
///
/// On success returns the gas + fee + nonce overrides ready to spread into
/// a `writeContract` call.
export async function prepareTx(
  params: PrepareTxParams
): Promise<PreparedTx> {
  const { publicClient, contractParams, totalValue, opts } = params;

  // Stage 1: balance.
  if (!opts?.skipPreflightChecks) {
    const acctAddr =
      typeof contractParams.account === "string"
        ? contractParams.account
        : contractParams.account.address;
    await preflightBalanceCheck(publicClient, acctAddr, totalValue);
  }

  // Stage 2 + 3: gas estimation. Reverts surface as decoded `QuipError`
  // subclasses; non-revert failures surface as `GasEstimationError`.
  let estimate: bigint;
  if (opts?.gas !== undefined) {
    estimate = opts.gas;
  } else {
    try {
      estimate = await publicClient.estimateContractGas(
        contractParams as Parameters<PublicClient["estimateContractGas"]>[0]
      );
    } catch (err) {
      const decoded = decodeContractError(err);
      if (decoded) throw decoded;
      const message =
        err instanceof Error ? err.message : String(err);
      throw new GasEstimationError(message, { cause: err });
    }
  }

  const gas =
    opts?.gas !== undefined ? opts.gas : applyGasBuffer(estimate, opts);

  const prepared: PreparedTx = {
    gas,
    fees: resolveFeeOptions(opts),
  };
  if (opts?.nonce !== undefined) prepared.nonce = opts.nonce;
  return prepared;
}

/// Re-export the upstream `QuipError` so callers writing `instanceof QuipError`
/// guards in gas-related code paths don't have to import from a separate
/// module.
export { QuipError };
