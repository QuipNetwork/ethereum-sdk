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
import { type PublicClient } from "viem";

import { GasEstimationError, QuipError } from "./errors.js";
import { decodeContractError } from "./internal/decodeError.js";

// The transaction-shaping primitives (multiplier clamp, fee resolution, balance
// preflight) are contract-agnostic, so the Shrincs SDK reuses the v1
// implementations verbatim. Only `prepareTx` is reimplemented here, because its
// revert decoding must run through the SHRINCS error registry rather than the
// WOTS+ one.
export {
  DEFAULT_GAS_MULTIPLIER,
  MIN_GAS_MULTIPLIER,
  MAX_GAS_MULTIPLIER,
  applyGasMultiplier,
  resolveGasMultiplier,
  resolveFeeOptions,
  preflightBalanceCheck,
  type TxOptions,
  type FeeOverrides,
  type PreparedTx,
  type ContractCallParams,
  type PrepareTxParams,
} from "../gas.js";
export { QuipError };

import {
  applyGasMultiplier,
  preflightBalanceCheck,
  resolveFeeOptions,
  type PrepareTxParams,
  type PreparedTx,
} from "../gas.js";

/// Run pre-flight balance + gas estimation, surfacing distinct typed errors per
/// stage (mirrors v1 `prepareTx`):
///   1. `BalanceTooLowError` — account can't cover `totalValue`.
///   2. Decoded SHRINCS `QuipError` — `estimateContractGas` reverted with a
///      recognized contract error.
///   3. `GasEstimationError` — estimation failed for a non-contract reason.
export async function prepareTx(params: PrepareTxParams): Promise<PreparedTx> {
  const { publicClient, contractParams, totalValue, opts } = params;

  if (!opts?.skipPreflightChecks) {
    const acctAddr =
      typeof contractParams.account === "string"
        ? contractParams.account
        : contractParams.account.address;
    await preflightBalanceCheck(publicClient, acctAddr, totalValue);
  }

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
      const message = err instanceof Error ? err.message : String(err);
      throw new GasEstimationError(message, { cause: err });
    }
  }

  const gas =
    opts?.gas !== undefined ? opts.gas : applyGasMultiplier(estimate, opts);

  const prepared: PreparedTx = { gas, fees: resolveFeeOptions(opts) };
  if (opts?.nonce !== undefined) prepared.nonce = opts.nonce;
  return prepared;
}
