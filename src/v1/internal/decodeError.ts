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
import { type Hex } from "viem";

import { wotsPlusImplementationAbi } from "../abi/WOTSPlusImplementation.js";
import { walletFactoryAbi } from "../abi/WalletFactory.js";
import { quipPaymasterAbi } from "../abi/QuipPaymaster.js";

import {
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
import {
  type ErrorFactory,
  makeErrorDecoder,
} from "./errorDecoder.js";

/// Map a Solidity error name to a typed-class factory. Each factory receives
/// the decoded `args` array (per the ABI) plus the QuipErrorOptions to attach
/// `selector`, `data`, and `cause`.
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
  //   - `IWOTSPlusImplementation.MalformedPayload()` (zero-arg, wallet belt-and-suspenders)
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

const decoder = makeErrorDecoder({
  abis: [wotsPlusImplementationAbi, walletFactoryAbi, quipPaymasterAbi],
  errorMap: ERROR_REGISTRY,
  unknownError: (name, args, opts) => new UnknownContractError(name, args, opts),
});

/// Decode an arbitrary error caught from viem into a typed `QuipError`.
/// Returns `null` when the input is not a contract revert we recognize at
/// all (caller should bubble the original error).
export function decodeContractError(err: unknown): QuipError | null {
  return decoder.decodeContractError(err);
}

/// Decode raw revert bytes (selector + abi-encoded args) into a typed
/// `QuipError`. Returns `null` for empty/unrecognized payloads (e.g. the
/// `0x` revert with no reason, or selectors outside the Quip surface).
///
/// Used by the `ExecutionReverted` event parser to turn the inner call's
/// raw revert into a typed reason instead of an opaque hex blob.
export function decodeRevertBytes(data: Hex): QuipError | null {
  return decoder.decodeRevertBytes(data);
}

/// Wrap a promise so that any contract-revert error it throws is decoded
/// into a typed `QuipError`. Non-contract errors bubble unchanged so the
/// caller can still handle network/timeout/etc.
export async function withDecodedError<T>(promise: Promise<T>): Promise<T> {
  return decoder.withDecodedError(promise);
}
