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
import { type Address, type PublicClient, type StateOverride } from "viem";

import {
  type ContractCallParams,
  type TxOptions,
  MIN_GAS_MULTIPLIER,
  applyGasMultiplier,
  prepareTx,
} from "./gas.js";

const SIMULATED_GAS_ALLOWANCE = 30_000_000n;

export interface CostEstimate {
  gasUnits: bigint;
  gasPrice: bigint;
  expectedGasUnits: bigint;
  expectedGasPrice: bigint;
}

export interface FeePerGas {
  cap: bigint;
  expected: bigint;
}

function solventSenderOverride(
  account: Address,
  totalValue: bigint,
  feeCap: bigint
): StateOverride {
  return [
    {
      address: account,
      balance: totalValue + feeCap * SIMULATED_GAS_ALLOWANCE,
    },
  ];
}

export async function resolveFeePerGas(
  publicClient: PublicClient,
  opts: TxOptions
): Promise<FeePerGas> {
  const pinnedByCaller = opts.maxFeePerGas ?? opts.gasPrice;
  if (pinnedByCaller !== undefined) {
    return { cap: pinnedByCaller, expected: pinnedByCaller };
  }
  const eip1559 = await tryResolveEip1559FeePerGas(publicClient);
  if (eip1559) return eip1559;

  const legacyPrice = await publicClient.getGasPrice();
  return { cap: legacyPrice, expected: legacyPrice };
}

async function tryResolveEip1559FeePerGas(
  publicClient: PublicClient
): Promise<FeePerGas | null> {
  let maxFeePerGas: bigint | undefined;
  let maxPriorityFeePerGas: bigint | undefined;
  try {
    ({ maxFeePerGas, maxPriorityFeePerGas } =
      await publicClient.estimateFeesPerGas());
  } catch {
    // Chain does not support EIP-1559 fee estimation — caller falls back to legacy gas price.
    return null;
  }
  if (maxFeePerGas === undefined) return null;

  // A valid 1559 cap is already in hand. `baseFeePerGas` only refines `expected`;
  // a failed block read must NOT discard the cap and silently downgrade the whole
  // quote to legacy pricing — fall back `expected` to the cap instead.
  let baseFeePerGas: bigint | null | undefined;
  try {
    ({ baseFeePerGas } = await publicClient.getBlock());
  } catch {
    baseFeePerGas = undefined;
  }
  return {
    cap: maxFeePerGas,
    expected:
      baseFeePerGas === null || baseFeePerGas === undefined
        ? maxFeePerGas
        : baseFeePerGas + (maxPriorityFeePerGas ?? 0n),
  };
}

export async function estimateTxCost(params: {
  publicClient: PublicClient;
  account: Address;
  contractCall: ContractCallParams;
  totalValue: bigint;
  opts: TxOptions;
}): Promise<CostEstimate> {
  const { publicClient, account, contractCall, totalValue, opts } = params;

  const feePerGas = await resolveFeePerGas(publicClient, opts);
  const measured = await prepareTx({
    publicClient,
    contractParams: {
      ...contractCall,
      stateOverride: solventSenderOverride(account, totalValue, feePerGas.cap),
    },
    totalValue,
    opts: {
      ...opts,
      skipPreflightChecks: true,
      gasMultiplier: MIN_GAS_MULTIPLIER,
    },
  });

  return {
    gasUnits:
      opts.gas !== undefined
        ? measured.gas
        : applyGasMultiplier(measured.gas, opts),
    gasPrice: feePerGas.cap,
    expectedGasUnits: measured.gas,
    expectedGasPrice: feePerGas.expected,
  };
}
