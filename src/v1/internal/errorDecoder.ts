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
  type Abi,
  type Hex,
  BaseError,
  ContractFunctionRevertedError,
  decodeErrorResult,
  toFunctionSelector,
} from "viem";

import { type QuipErrorOptions, QuipError } from "../errors.js";

/// Map a Solidity error name to a typed-class factory. Each factory receives
/// the decoded `args` array (per the ABI) plus the QuipErrorOptions to attach
/// `selector`, `data`, and `cause`.
export type ErrorFactory = (
  args: readonly unknown[],
  opts: QuipErrorOptions
) => QuipError;

export type UnknownErrorFactory = (
  errorName: string | undefined,
  args: readonly unknown[] | undefined,
  opts?: QuipErrorOptions
) => QuipError;

export interface ErrorDecoderRegistry {
  /// `as const` generated ABIs are tuples of fragments, not `Abi`, so accept
  /// any readonly fragment list.
  abis: readonly (readonly Abi[number][])[];
  errorMap: Readonly<Record<string, ErrorFactory>>;
  unknownError: UnknownErrorFactory;
}

export interface ErrorDecoder {
  decodeContractError: (err: unknown) => QuipError | null;
  decodeRevertBytes: (data: Hex) => QuipError | null;
  withDecodedError: <T>(promise: Promise<T>) => Promise<T>;
}

interface ExtractedRevert {
  errorName?: string;
  args?: readonly unknown[];
  selector?: Hex;
  data?: Hex;
}

function combineErrorAbi(abis: readonly (readonly Abi[number][])[]): Abi {
  const seen = new Set<string>();
  const merged: Abi[number][] = [];
  for (const abi of abis) {
    for (const fragment of abi) {
      if (fragment.type !== "error") continue;
      // Dedup key: error name + input type signature, since the same
      // `RenounceDisabled()` appears verbatim in multiple contracts.
      const key = `${fragment.name}(${(fragment.inputs ?? [])
        .map((i) => i.type)
        .join(",")})`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(fragment);
    }
  }
  return merged;
}

function selectorTable(combined: Abi): Record<Hex, string> {
  const out: Record<Hex, string> = {};
  for (const fragment of combined) {
    if (fragment.type !== "error") continue;
    const sig = `${fragment.name}(${(fragment.inputs ?? [])
      .map((i) => i.type)
      .join(",")})`;
    out[toFunctionSelector(sig)] = fragment.name;
  }
  return out;
}

function isHex(value: unknown): value is Hex {
  return (
    typeof value === "string" &&
    value.length >= 10 &&
    /^0x[0-9a-fA-F]*$/.test(value)
  );
}

/// Shared decode machinery parameterized by ABI fragments + an error-class
/// registry. `/v1` and SHRINCS each bind their own map; public signatures on
/// those modules stay unchanged.
export function makeErrorDecoder(
  registry: ErrorDecoderRegistry
): ErrorDecoder {
  const combinedAbi = combineErrorAbi(registry.abis);
  const selectorToName = selectorTable(combinedAbi);

  function decodeRaw(raw: Hex): ExtractedRevert | null {
    if (raw.length < 10) return null;
    const selector = raw.slice(0, 10) as Hex;
    try {
      const decoded = decodeErrorResult({
        abi: combinedAbi,
        data: raw,
      });
      return {
        errorName: decoded.errorName,
        args: decoded.args ?? [],
        selector,
        data: raw,
      };
    } catch {
      return {
        errorName: selectorToName[selector],
        selector,
        data: raw,
      };
    }
  }

  function selectorForName(errorName: string): Hex | undefined {
    for (const fragment of combinedAbi) {
      if (fragment.type !== "error" || fragment.name !== errorName) continue;
      const sig = `${fragment.name}(${(fragment.inputs ?? [])
        .map((i) => i.type)
        .join(",")})`;
      return toFunctionSelector(sig);
    }
    return undefined;
  }

  /// Walk a viem `BaseError` chain looking for revert data. We try, in order:
  ///   1. A `ContractFunctionRevertedError` with decoded `data` (writeContract /
  ///      readContract path — viem already decoded against the call's ABI).
  ///   2. A `ContractFunctionRevertedError` with `raw` bytes — decode ourselves.
  ///   3. Any error in the cause chain with a `.data` hex string — covers
  ///      `deployContract` and other low-level paths where viem doesn't wrap
  ///      the revert as a ContractFunctionRevertedError.
  function extractRevert(err: unknown): ExtractedRevert | null {
    if (!(err instanceof BaseError)) return null;

    const reverted = err.walk(
      (e) => e instanceof ContractFunctionRevertedError
    ) as ContractFunctionRevertedError | null;
    if (reverted) {
      if (reverted.data) {
        const selector = selectorForName(reverted.data.errorName);
        return {
          errorName: reverted.data.errorName,
          args: reverted.data.args ?? [],
          ...(selector && { selector }),
        };
      }
      if (reverted.raw) {
        const fromRaw = decodeRaw(reverted.raw);
        if (fromRaw) return fromRaw;
      }
    }

    let found: ExtractedRevert | null = null;
    err.walk((e) => {
      if (found) return false;
      const data = (e as { data?: unknown })?.data;
      if (!isHex(data) || data.length < 10) return false;
      const selector = data.slice(0, 10) as Hex;
      if (!(selector in selectorToName)) return false;
      found = decodeRaw(data);
      return true;
    });
    return found;
  }

  function decodeContractError(err: unknown): QuipError | null {
    const extracted = extractRevert(err);
    if (!extracted) return null;

    const opts: QuipErrorOptions = {
      cause: err,
      ...(extracted.selector && { selector: extracted.selector }),
      ...(extracted.data && { data: extracted.data }),
    };

    const factory = extracted.errorName
      ? registry.errorMap[extracted.errorName]
      : undefined;
    if (factory) {
      return factory(extracted.args ?? [], opts);
    }

    return registry.unknownError(extracted.errorName, extracted.args, opts);
  }

  function decodeRevertBytes(data: Hex): QuipError | null {
    if (!data || data.length < 10) return null;
    const extracted = decodeRaw(data);
    if (!extracted) return null;

    const opts: QuipErrorOptions = {
      ...(extracted.selector && { selector: extracted.selector }),
      ...(extracted.data && { data: extracted.data }),
    };

    const factory = extracted.errorName
      ? registry.errorMap[extracted.errorName]
      : undefined;
    if (factory) {
      return factory(extracted.args ?? [], opts);
    }
    return registry.unknownError(extracted.errorName, extracted.args, opts);
  }

  async function withDecodedError<T>(promise: Promise<T>): Promise<T> {
    try {
      return await promise;
    } catch (err) {
      const decoded = decodeContractError(err);
      if (decoded) throw decoded;
      throw err;
    }
  }

  return { decodeContractError, decodeRevertBytes, withDecodedError };
}
