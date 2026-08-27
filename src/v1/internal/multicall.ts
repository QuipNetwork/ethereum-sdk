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
  type ContractFunctionParameters,
  type PublicClient,
} from "viem";

import { CHAIN_IDS } from "../addresses.js";
import { withDecodedError } from "./decodeError.js";

/// Canonical Multicall3 deployment address. Present on every major EVM chain
/// (mainnet, all OP-Stack L2s, Base, Sepolia, etc.) at this CREATE2-derived
/// address. See https://www.multicall3.com.
export const MULTICALL3_ADDRESS: Address =
  "0xcA11bde05977b3631167028862bE2a173976CA11";

/// Chains where Multicall3 is known not to be deployed. Probed lazily on
/// first call for any other chain.
const KNOWN_UNAVAILABLE: ReadonlySet<number> = new Set([
  CHAIN_IDS.MIDL_TESTNET,
]);

/// Per-chain cache: chains we've probed and confirmed have no Multicall3.
/// Subsequent calls skip the probe and go straight to sequential reads.
const unavailableCache = new Set<number>(KNOWN_UNAVAILABLE);

/// Returns the Multicall3 address for `chainId`, or `null` if multicall is
/// known unavailable. Pure lookup — no RPC probe.
export function getMulticall3Address(chainId: number): Address | null {
  if (KNOWN_UNAVAILABLE.has(chainId)) return null;
  return MULTICALL3_ADDRESS;
}

/// Result shape of `tryMulticall` — mirrors viem's `MulticallResults` with
/// `allowFailure: true`. Callers narrow `status` to "success" before reading
/// `result`.
export type TryMulticallResult<T> =
  | { status: "success"; result: T }
  | { status: "failure"; error: Error; result?: undefined };

interface TryMulticallOptions {
  chainId?: number;
  /// Disable Multicall3 path entirely; useful for tests asserting the
  /// sequential fallback returns identical results.
  forceSequential?: boolean;
}

/// Read multiple contract methods in one round-trip via Multicall3, falling
/// back to sequential `readContract` calls when:
///   - the chain is known to lack Multicall3, or
///   - a previous call on this chain probed and failed, or
///   - the caller asked for the sequential path explicitly.
///
/// Always returns `{status, result}` per call (allowFailure semantics) so
/// out-of-bounds array reads (`commitments[N]` past the end) become `failure`
/// entries instead of throwing.
export async function tryMulticall<
  TCalls extends readonly ContractFunctionParameters[],
>(
  publicClient: PublicClient,
  calls: TCalls,
  opts?: TryMulticallOptions
): Promise<{ [K in keyof TCalls]: TryMulticallResult<unknown> }> {
  if (calls.length === 0) {
    return [] as unknown as { [K in keyof TCalls]: TryMulticallResult<unknown> };
  }

  const chainId = opts?.chainId ?? (await publicClient.getChainId());

  const useSequential = opts?.forceSequential || unavailableCache.has(chainId);
  if (useSequential) {
    return sequentialFallback(publicClient, calls);
  }

  const multicallAddress = getMulticall3Address(chainId);
  if (!multicallAddress) {
    return sequentialFallback(publicClient, calls);
  }

  // Probe the canonical Multicall3 address for deployed code. viem's
  // `multicall` doesn't throw when the address has no code — it returns
  // every entry as `failure` (silently) — so a code-presence check is the
  // only reliable way to detect Multicall3 absence on a fresh chain (e.g.
  // a freshly-spun Anvil instance).
  try {
    const code = await publicClient.getCode({ address: multicallAddress });
    if (!code || code === "0x") {
      unavailableCache.add(chainId);
      return sequentialFallback(publicClient, calls);
    }
  } catch {
    unavailableCache.add(chainId);
    return sequentialFallback(publicClient, calls);
  }

  try {
    const results = (await publicClient.multicall({
      contracts: calls as unknown as ContractFunctionParameters[],
      allowFailure: true,
      multicallAddress,
    })) as unknown as { [K in keyof TCalls]: TryMulticallResult<unknown> };
    return results;
  } catch {
    unavailableCache.add(chainId);
    return sequentialFallback(publicClient, calls);
  }
}

async function sequentialFallback<
  TCalls extends readonly ContractFunctionParameters[],
>(
  publicClient: PublicClient,
  calls: TCalls
): Promise<{ [K in keyof TCalls]: TryMulticallResult<unknown> }> {
  const out: TryMulticallResult<unknown>[] = [];
  for (const call of calls) {
    try {
      const result = await withDecodedError(
        publicClient.readContract({
          address: call.address,
          abi: call.abi,
          functionName: call.functionName,
          ...(call.args !== undefined && { args: call.args }),
        } as Parameters<PublicClient["readContract"]>[0])
      );
      out.push({ status: "success", result });
    } catch (error) {
      out.push({
        status: "failure",
        error: error instanceof Error ? error : new Error(String(error)),
      });
    }
  }
  return out as { [K in keyof TCalls]: TryMulticallResult<unknown> };
}

/// Test-only: clear the unavailable-chain cache so a forceSequential test
/// can be followed by a non-forced test that re-probes Multicall3.
export function resetMulticallCacheForTesting(): void {
  unavailableCache.clear();
  for (const id of KNOWN_UNAVAILABLE) unavailableCache.add(id);
}
