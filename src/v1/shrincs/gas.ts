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
import { QuipError } from "./errors.js";
import { decodeContractError } from "./internal/decodeError.js";
import { prepareTxCore } from "../gas.js";

// The transaction-shaping primitives (multiplier clamp, fee resolution, balance
// preflight) are contract-agnostic, so the Shrincs SDK reuses the v1
// implementations verbatim. Only `prepareTx` is rebound here, because its
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
  return prepareTxCore(params, decodeContractError);
}
