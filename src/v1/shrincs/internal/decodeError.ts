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

import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import { shrincsPaymasterAbi } from "../abi/ShrincsPaymaster.js";

import {
  type QuipErrorOptions,
  QuipError,
  // Wallet
  ZeroAddressFactoryError,
  ZeroAddressOwnerError,
  InvalidFactoryError,
  InvalidSignatureError,
  CommitmentMismatchError,
  ZeroErc1271CommitmentError,
  ZeroMaxSignaturesError,
  UnsupportedHashSuiteError,
  StaleStatefulLeafError,
  StatefulBudgetExhaustedError,
  ImplementationNotVettedError,
  ImplementationDeprecatedError,
  NotUpgradingError,
  GuardedSlotTamperedError,
  MalformedCodecPayloadError,
  RenounceDisabledError,
  ClassicalWithdrawDisabledError,
  ClassicalTransferOwnershipDisabledError,
  OwnershipHandoverDisabledError,
  StorageStoreDisabledError,
  DelegateExecuteDisabledError,
  // Paymaster
  InvalidEntryPointError,
  ZeroCommitmentError,
  // Generic
  UnauthorizedError,
  AlreadyInitializedError,
  // Fallback
  UnknownContractError,
} from "../errors.js";

/// Combined error-fragment ABI used by `decodeErrorResult`. Built once at module
/// load by deduping error fragments across the wallet + paymaster ABIs (the same
/// error, e.g. `ZeroMaxSignatures()`, appears in both).
const COMBINED_ERROR_ABI: Abi = (() => {
  const seen = new Set<string>();
  const merged: Abi[number][] = [];
  for (const fragment of [...shrincsWalletAbi, ...shrincsPaymasterAbi] as Abi) {
    if (fragment.type !== "error") continue;
    const key = `${fragment.name}(${(fragment.inputs ?? [])
      .map((i) => i.type)
      .join(",")})`;
    if (seen.has(key)) continue;
    seen.add(key);
    merged.push(fragment);
  }
  return merged;
})();

type ErrorFactory = (
  args: readonly unknown[],
  opts: QuipErrorOptions
) => QuipError;

const ERROR_REGISTRY: Record<string, ErrorFactory> = {
  // Wallet
  ZeroAddressFactory: (_, o) => new ZeroAddressFactoryError(o),
  ZeroAddressOwner: (_, o) => new ZeroAddressOwnerError(o),
  InvalidFactory: (_, o) => new InvalidFactoryError(o),
  InvalidSignature: (_, o) => new InvalidSignatureError(o),
  CommitmentMismatch: (_, o) => new CommitmentMismatchError(undefined, undefined, o),
  ZeroErc1271Commitment: (_, o) => new ZeroErc1271CommitmentError(o),
  ZeroMaxSignatures: (_, o) => new ZeroMaxSignaturesError(o),
  UnsupportedHashSuite: (_, o) => new UnsupportedHashSuiteError(o),
  StaleStatefulLeaf: (_, o) => new StaleStatefulLeafError(undefined, o),
  StatefulBudgetExhausted: (_, o) =>
    new StatefulBudgetExhaustedError(undefined, undefined, o),
  ImplementationNotVetted: (_, o) => new ImplementationNotVettedError(o),
  ImplementationDeprecated: (_, o) => new ImplementationDeprecatedError(o),
  NotUpgrading: (_, o) => new NotUpgradingError(o),
  GuardedSlotTampered: (args, o) =>
    new GuardedSlotTamperedError(Number(args[0]), o),
  // `ShrincsWalletCodec.MalformedPayload(uint256 expectedMin, uint256 actual)`.
  MalformedPayload: (args, o) =>
    new MalformedCodecPayloadError(args[0] as bigint, args[1] as bigint, o),
  RenounceDisabled: (_, o) => new RenounceDisabledError(o),
  ClassicalWithdrawDisabled: (_, o) => new ClassicalWithdrawDisabledError(o),
  ClassicalTransferOwnershipDisabled: (_, o) =>
    new ClassicalTransferOwnershipDisabledError(o),
  OwnershipHandoverDisabled: (_, o) => new OwnershipHandoverDisabledError(o),
  StorageStoreDisabled: (_, o) => new StorageStoreDisabledError(o),
  DelegateExecuteDisabled: (_, o) => new DelegateExecuteDisabledError(o),

  // Paymaster
  InvalidEntryPoint: (_, o) => new InvalidEntryPointError(o),
  ZeroCommitment: (_, o) => new ZeroCommitmentError(o),

  // Generic (solady/oz)
  Unauthorized: (_, o) => new UnauthorizedError(o),
  AlreadyInitialized: (_, o) => new AlreadyInitializedError(o),
};

const SELECTOR_TO_NAME: Record<Hex, string> = (() => {
  const out: Record<Hex, string> = {};
  for (const fragment of COMBINED_ERROR_ABI) {
    if (fragment.type !== "error") continue;
    const sig = `${fragment.name}(${(fragment.inputs ?? [])
      .map((i) => i.type)
      .join(",")})`;
    out[toFunctionSelector(sig)] = fragment.name;
  }
  return out;
})();

interface ExtractedRevert {
  errorName?: string;
  args?: readonly unknown[];
  selector?: Hex;
  data?: Hex;
}

function isHex(value: unknown): value is Hex {
  return (
    typeof value === "string" &&
    value.length >= 10 &&
    /^0x[0-9a-fA-F]*$/.test(value)
  );
}

function decodeRaw(raw: Hex): ExtractedRevert | null {
  if (raw.length < 10) return null;
  const selector = raw.slice(0, 10) as Hex;
  try {
    const decoded = decodeErrorResult({ abi: COMBINED_ERROR_ABI, data: raw });
    return {
      errorName: decoded.errorName,
      args: decoded.args ?? [],
      selector,
      data: raw,
    };
  } catch {
    return { errorName: SELECTOR_TO_NAME[selector], selector, data: raw };
  }
}

function selectorForName(errorName: string): Hex | undefined {
  for (const fragment of COMBINED_ERROR_ABI) {
    if (fragment.type !== "error" || fragment.name !== errorName) continue;
    const sig = `${fragment.name}(${(fragment.inputs ?? [])
      .map((i) => i.type)
      .join(",")})`;
    return toFunctionSelector(sig);
  }
  return undefined;
}

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
    if (!(selector in SELECTOR_TO_NAME)) return false;
    found = decodeRaw(data);
    return true;
  });
  return found;
}

/// Decode an arbitrary error caught from viem into a typed `QuipError`. Returns
/// `null` when the input is not a contract revert we recognize at all (caller
/// should bubble the original error).
export function decodeContractError(err: unknown): QuipError | null {
  const extracted = extractRevert(err);
  if (!extracted) return null;

  const opts: QuipErrorOptions = {
    cause: err,
    ...(extracted.selector && { selector: extracted.selector }),
    ...(extracted.data && { data: extracted.data }),
  };

  const factory = extracted.errorName
    ? ERROR_REGISTRY[extracted.errorName]
    : undefined;
  if (factory) return factory(extracted.args ?? [], opts);

  return new UnknownContractError(extracted.errorName, extracted.args, opts);
}

/// Decode raw revert bytes (selector + abi-encoded args) into a typed
/// `QuipError`. Returns `null` for empty/unrecognized payloads.
export function decodeRevertBytes(data: Hex): QuipError | null {
  if (!data || data.length < 10) return null;
  const extracted = decodeRaw(data);
  if (!extracted) return null;

  const opts: QuipErrorOptions = {
    ...(extracted.selector && { selector: extracted.selector }),
    ...(extracted.data && { data: extracted.data }),
  };

  const factory = extracted.errorName
    ? ERROR_REGISTRY[extracted.errorName]
    : undefined;
  if (factory) return factory(extracted.args ?? [], opts);
  return new UnknownContractError(extracted.errorName, extracted.args, opts);
}

/// Wrap a promise so any contract-revert error it throws is decoded into a typed
/// `QuipError`. Non-contract errors bubble unchanged.
export async function withDecodedError<T>(promise: Promise<T>): Promise<T> {
  try {
    return await promise;
  } catch (err) {
    const decoded = decodeContractError(err);
    if (decoded) throw decoded;
    throw err;
  }
}
