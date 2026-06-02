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

import { quipWalletAbi } from "../abi/QuipWallet.js";
import { quipFactoryAbi } from "../abi/QuipFactory.js";
import { quipPaymasterAbi } from "../abi/QuipPaymaster.js";

import {
  type QuipErrorOptions,
  QuipError,
  // Wallet
  ZeroAddressFactoryError,
  ZeroAddressOwnerError,
  InvalidFactoryError,
  InvalidSignatureError,
  RenounceDisabledError,
  ClassicalWithdrawDisabledError,
  ClassicalTransferOwnershipDisabledError,
  OwnershipHandoverDisabledError,
  OnlyWalletError,
  OwnerStateMismatchError,
  SameOwnerError,
  RegistryDesyncError,
  ZeroVaultIdError,
  DuplicateKeyError,
  KeyInUseError,
  SameKeyError,
  UnknownKeyError,
  KeyAdditionFailedError,
  KeyRemovalFailedError,
  EmptyKeysError,
  IncorrectRecoveryKeyAmountError,
  IncorrectVerificationKeyAmountError,
  InvalidSigningKeysetError,
  MalformedCodecPayloadError,
  MalformedPayloadError,
  NotUpgradingError,
  IncorrectTransactionKeyAmountError,
  ImplementationNotVettedError,
  ImplementationDeprecatedError,
  UnknownDisasterRecoveryKeyError,
  UnknownOwnershipKeyError,
  GuardedSlotTamperedError,
  GuardedSlotWriteDeniedError,
  // Factory
  InsufficientBalanceError,
  FeeExceedsMaxError,
  EmptyCodeError,
  AlreadyVettedError,
  NotDeprecatedError,
  NoActiveImplementationError,
  InsufficientCreationFeeError,
  ZeroMaxFeeError,
  // Paymaster
  InvalidEntryPointError,
  ZeroValuePqVerifierKeyError,
  PqVerifierNotRegisteredError,
  VerifierKeyInUseError,
  // Fallback
  UnknownContractError,
} from "../errors.js";

/// Combined error-fragment ABI used by `decodeErrorResult`. Built once at
/// module load by deduping error fragments across the three Quip ABIs.
const COMBINED_ERROR_ABI: Abi = (() => {
  const seen = new Set<string>();
  const merged: Abi[number][] = [];
  for (const fragment of [
    ...quipWalletAbi,
    ...quipFactoryAbi,
    ...quipPaymasterAbi,
  ]) {
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
  return merged;
})();

/// Map a Solidity error name to a typed-class factory. Each factory receives
/// the decoded `args` array (per the ABI) plus the QuipErrorOptions to attach
/// `selector`, `data`, and `cause`.
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
  RenounceDisabled: (_, o) => new RenounceDisabledError(o),
  ClassicalWithdrawDisabled: (_, o) => new ClassicalWithdrawDisabledError(o),
  ClassicalTransferOwnershipDisabled: (_, o) =>
    new ClassicalTransferOwnershipDisabledError(o),
  OwnershipHandoverDisabled: (_, o) => new OwnershipHandoverDisabledError(o),
  OnlyWallet: (_, o) => new OnlyWalletError(o),
  OwnerStateMismatch: (_, o) => new OwnerStateMismatchError(o),
  SameOwner: (_, o) => new SameOwnerError(o),
  RegistryDesync: (_, o) => new RegistryDesyncError(o),
  ZeroVaultId: (_, o) => new ZeroVaultIdError(o),
  DuplicateKey: (_, o) => new DuplicateKeyError(o),
  KeyInUse: (_, o) => new KeyInUseError(o),
  SameKey: (_, o) => new SameKeyError(o),
  UnknownKey: (_, o) => new UnknownKeyError(o),
  KeyAdditionFailed: (_, o) => new KeyAdditionFailedError(o),
  KeyRemovalFailed: (_, o) => new KeyRemovalFailedError(o),
  EmptyKeys: (_, o) => new EmptyKeysError(o),
  IncorrectRecoveryKeyAmount: (_, o) =>
    new IncorrectRecoveryKeyAmountError(o),
  IncorrectVerificationKeyAmount: (_, o) =>
    new IncorrectVerificationKeyAmountError(o),
  InvalidSigningKeyset: (_, o) => new InvalidSigningKeysetError(o),
  // Two distinct contract errors share the name `MalformedPayload`:
  //   - `IQuipWallet.MalformedPayload()` (zero-arg, wallet belt-and-suspenders)
  //   - `WOTSPlusCodec.MalformedPayload(uint256,uint256)` (codec size mismatch)
  // Dispatch on args length so the codec variant preserves expected/actual.
  MalformedPayload: (args, o) =>
    args.length === 2
      ? new MalformedCodecPayloadError(args[0] as bigint, args[1] as bigint, o)
      : new MalformedPayloadError(o),
  NotUpgrading: (_, o) => new NotUpgradingError(o),
  IncorrectTransactionKeyAmount: (_, o) =>
    new IncorrectTransactionKeyAmountError(o),
  ImplementationNotVetted: (_, o) => new ImplementationNotVettedError(o),
  ImplementationDeprecated: (_, o) => new ImplementationDeprecatedError(o),
  UnknownDisasterRecoveryKey: (_, o) =>
    new UnknownDisasterRecoveryKeyError(o),
  UnknownOwnershipKey: (_, o) => new UnknownOwnershipKeyError(o),
  GuardedSlotTampered: (args, o) =>
    new GuardedSlotTamperedError(Number(args[0]), o),
  GuardedSlotWriteDenied: (_, o) => new GuardedSlotWriteDeniedError(o),

  // Factory
  InsufficientBalance: (args, o) =>
    new InsufficientBalanceError(args[0] as bigint, args[1] as bigint, o),
  FeeExceedsMax: (args, o) =>
    new FeeExceedsMaxError(args[0] as bigint, args[1] as bigint, o),
  EmptyCode: (_, o) => new EmptyCodeError(o),
  AlreadyVetted: (_, o) => new AlreadyVettedError(o),
  NotDeprecated: (_, o) => new NotDeprecatedError(o),
  NoActiveImplementation: (_, o) => new NoActiveImplementationError(o),
  InsufficientCreationFee: (args, o) =>
    new InsufficientCreationFeeError(args[0] as bigint, args[1] as bigint, o),
  ZeroMaxFee: (_, o) => new ZeroMaxFeeError(o),

  // Paymaster
  InvalidEntryPoint: (_, o) => new InvalidEntryPointError(o),
  ZeroValuePqVerifierKey: (_, o) => new ZeroValuePqVerifierKeyError(o),
  PqVerifierNotRegistered: (_, o) => new PqVerifierNotRegisteredError(o),
  VerifierKeyInUse: (_, o) => new VerifierKeyInUseError(o),
};

/// Lookup table from 4-byte selector → error name. Built once at module load
/// from the dedup'd combined ABI. Used as a fallback when viem hands us
/// `raw` revert bytes without an attached `errorName`.
const SELECTOR_TO_NAME: Record<Hex, string> = (() => {
  const out: Record<Hex, string> = {};
  for (const fragment of COMBINED_ERROR_ABI) {
    if (fragment.type !== "error") continue;
    const sig = `${fragment.name}(${(fragment.inputs ?? [])
      .map((i) => i.type)
      .join(",")})`;
    const selector = toFunctionSelector(sig);
    out[selector] = fragment.name;
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

/// Decode raw revert bytes against our combined ABI. Returns null if the
/// selector is unknown.
function decodeRaw(raw: Hex): ExtractedRevert | null {
  if (raw.length < 10) return null;
  const selector = raw.slice(0, 10) as Hex;
  try {
    const decoded = decodeErrorResult({
      abi: COMBINED_ERROR_ABI,
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
      errorName: SELECTOR_TO_NAME[selector],
      selector,
      data: raw,
    };
  }
}

/// Reconstruct the 4-byte selector for a decoded error fragment by looking
/// up the canonical signature in our combined ABI. Returns `undefined` if
/// the name doesn't match a known fragment (UnknownContractError path).
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

/// Walk a viem `BaseError` chain looking for revert data. We try, in order:
///   1. A `ContractFunctionRevertedError` with decoded `data` (writeContract /
///      readContract path — viem already decoded against the call's ABI).
///   2. A `ContractFunctionRevertedError` with `raw` bytes — decode ourselves.
///   3. Any error in the cause chain with a `.data` hex string — covers
///      `deployContract` and other low-level paths where viem doesn't wrap
///      the revert as a ContractFunctionRevertedError.
function extractRevert(err: unknown): ExtractedRevert | null {
  if (!(err instanceof BaseError)) return null;

  // Step 1 / 2: prefer the typed ContractFunctionRevertedError.
  const reverted = err.walk(
    (e) => e instanceof ContractFunctionRevertedError
  ) as ContractFunctionRevertedError | null;
  if (reverted) {
    if (reverted.data) {
      // viem decoded against the call's ABI but doesn't expose the original
      // 4-byte selector here. Reconstruct it from the canonical signature so
      // typed `QuipError`s always carry `.selector` for log forwarding.
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

  // Step 3: scan the whole chain for a `.data` hex blob whose 4-byte
  // selector matches a known Quip error. This covers `deployContract` and
  // other low-level paths where viem doesn't wrap the revert as a
  // `ContractFunctionRevertedError`. We require a known-selector match to
  // avoid false positives on adjacent `.data` fields (e.g. transaction
  // calldata, which would also pass `isHex`).
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

/// Decode an arbitrary error caught from viem into a typed `QuipError`.
/// Returns `null` when the input is not a contract revert we recognize at
/// all (caller should bubble the original error).
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
  if (factory) {
    return factory(extracted.args ?? [], opts);
  }

  return new UnknownContractError(extracted.errorName, extracted.args, opts);
}

/// Decode raw revert bytes (selector + abi-encoded args) into a typed
/// `QuipError`. Returns `null` for empty/unrecognized payloads (e.g. the
/// `0x` revert with no reason, or selectors outside the Quip surface).
///
/// Used by the `ExecutionReverted` event parser to turn the inner call's
/// raw revert into a typed reason instead of an opaque hex blob.
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
  if (factory) {
    return factory(extracted.args ?? [], opts);
  }
  return new UnknownContractError(extracted.errorName, extracted.args, opts);
}

/// Wrap a promise so that any contract-revert error it throws is decoded
/// into a typed `QuipError`. Non-contract errors bubble unchanged so the
/// caller can still handle network/timeout/etc.
export async function withDecodedError<T>(promise: Promise<T>): Promise<T> {
  try {
    return await promise;
  } catch (err) {
    const decoded = decodeContractError(err);
    if (decoded) throw decoded;
    throw err;
  }
}
