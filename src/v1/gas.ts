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
  type StateOverride,
} from "viem";

import {
  BalanceTooLowError,
  GasEstimationError,
  QuipError,
} from "./errors.js";
import { decodeContractError } from "./internal/decodeError.js";

/// Default multiplier applied to `eth_estimateGas` results. `1.2` =
/// estimate × 1.20 (20% safety margin), mirroring the existing
/// `executeWithWinternitz` heuristic.
export const DEFAULT_GAS_MULTIPLIER = 1.2;

/// Floor for `gasMultiplier`. Values below 1.0 would under-budget gas and
/// risk out-of-gas reverts mid-execution; clamped up to this value.
export const MIN_GAS_MULTIPLIER = 1.0;

/// Ceiling for `gasMultiplier`. Aligns with viem's `prepareUserOperation`
/// convention and keeps callers from accidentally requesting outrageously
/// high gas via misconfiguration.
export const MAX_GAS_MULTIPLIER = 2.0;

/// Per-call transaction-shaping options accepted by every write method on
/// the SDK. All fields are optional; unset values fall through to viem's
/// defaults (eth_gasPrice / eth_feeHistory / chain nonce manager).
export interface TxOptions {
  /// Explicit gas limit. When set, skips the `estimateContractGas` call and
  /// the multiplier step entirely.
  gas?: bigint;
  /// Multiplier applied to the gas estimate: `gas = floor(estimate * gasMultiplier)`.
  /// Default `DEFAULT_GAS_MULTIPLIER` (1.2 = 20% buffer). Clamped to
  /// `[MIN_GAS_MULTIPLIER, MAX_GAS_MULTIPLIER]` = `[1.0, 2.0]`. Non-finite
  /// values fall back to `MIN_GAS_MULTIPLIER` (no buffer).
  gasMultiplier?: number;
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

/// Apply the configured multiplier to a gas estimate.
/// `floor(estimate * mul)`, with `mul` clamped to `[MIN, MAX]`.
///
/// Internally scales by 1000 to preserve three decimal places of the
/// float multiplier under BigInt math without losing precision to
/// floating-point round-trips.
export function applyGasMultiplier(estimate: bigint, opts?: TxOptions): bigint {
  const mul = resolveGasMultiplier(opts);
  // Round to 3 decimal places to keep the BigInt arithmetic deterministic
  // (multipliers like 1.137 are honored to the third decimal).
  const scaled = Math.round(mul * 1000);
  return (estimate * BigInt(scaled)) / 1000n;
}

/// Resolve the effective gas multiplier from `TxOptions`, applying the
/// default + clamp. Exported for callers that want to inspect the
/// resolved value (e.g. logging, dashboards).
export function resolveGasMultiplier(opts?: TxOptions): number {
  let mul = opts?.gasMultiplier ?? DEFAULT_GAS_MULTIPLIER;
  if (!Number.isFinite(mul) || mul < MIN_GAS_MULTIPLIER) {
    mul = MIN_GAS_MULTIPLIER;
  }
  if (mul > MAX_GAS_MULTIPLIER) mul = MAX_GAS_MULTIPLIER;
  return mul;
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
  stateOverride?: StateOverride;
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
    opts?.gas !== undefined ? opts.gas : applyGasMultiplier(estimate, opts);

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
