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

import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import { shrincsPaymasterAbi } from "../abi/ShrincsPaymaster.js";

import {
  QuipError,
  // Wallet
  ZeroAddressFactoryError,
  ZeroAddressOwnerError,
  ZeroAddressVerifierError,
  InvalidFactoryError,
  InvalidSignatureError,
  CommitmentMismatchError,
  ZeroErc1271CommitmentError,
  ZeroMaxSignaturesError,
  UnsupportedHashSuiteError,
  StaleStatefulLeafError,
  StaleActionNonceError,
  EmptyLeavesError,
  LeafOutOfRangeError,
  ExecuteFeeExceedsCapError,
  StandardExecuteDisabledError,
  StatefulBudgetExhaustedError,
  StatefulTreeSpentError,
  StatelessTreeSpentError,
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
  // Generic
  UnauthorizedError,
  AlreadyInitializedError,
  // Fallback
  UnknownContractError,
} from "../errors.js";
import {
  type ErrorFactory,
  makeErrorDecoder,
} from "../../internal/errorDecoder.js";

const ERROR_REGISTRY: Record<string, ErrorFactory> = {
  // Wallet
  ZeroAddressFactory: (_, o) => new ZeroAddressFactoryError(o),
  ZeroAddressOwner: (_, o) => new ZeroAddressOwnerError(o),
  ZeroAddressVerifier: (_, o) => new ZeroAddressVerifierError(o),
  InvalidFactory: (_, o) => new InvalidFactoryError(o),
  InvalidSignature: (_, o) => new InvalidSignatureError(o),
  CommitmentMismatch: (_, o) => new CommitmentMismatchError(undefined, undefined, o),
  ZeroErc1271Commitment: (_, o) => new ZeroErc1271CommitmentError(o),
  ZeroMaxSignatures: (_, o) => new ZeroMaxSignaturesError(o),
  // `StatefulTreeSpent(bytes32 treeId)` (wallet + paymaster).
  StatefulTreeSpent: (args, o) => new StatefulTreeSpentError(args[0] as Hex, o),
  // `StatelessTreeSpent(bytes32 treeId)` (wallet).
  StatelessTreeSpent: (args, o) => new StatelessTreeSpentError(args[0] as Hex, o),
  UnsupportedHashSuite: (_, o) => new UnsupportedHashSuiteError(o),
  StaleStatefulLeaf: (_, o) => new StaleStatefulLeafError(undefined, o),
  StaleActionNonce: (args, o) =>
    new StaleActionNonceError(args[0] as bigint, args[1] as bigint, o),
  EmptyLeaves: (_, o) => new EmptyLeavesError(o),
  // `LeafOutOfRange(uint32 leaf)`.
  LeafOutOfRange: (args, o) => new LeafOutOfRangeError(Number(args[0]), undefined, o),
  // `ExecuteFeeExceedsCap(uint256 fee, uint256 maxFee)`.
  ExecuteFeeExceedsCap: (args, o) =>
    new ExecuteFeeExceedsCapError(args[0] as bigint, args[1] as bigint, o),
  StandardExecuteDisabled: (_, o) => new StandardExecuteDisabledError(o),
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

  // Generic (solady/oz)
  Unauthorized: (_, o) => new UnauthorizedError(o),
  AlreadyInitialized: (_, o) => new AlreadyInitializedError(o),
};

const decoder = makeErrorDecoder({
  abis: [shrincsWalletAbi, shrincsPaymasterAbi],
  errorMap: ERROR_REGISTRY,
  unknownError: (name, args, opts) => new UnknownContractError(name, args, opts),
});

/// Decode an arbitrary error caught from viem into a typed `QuipError`. Returns
/// `null` when the input is not a contract revert we recognize at all (caller
/// should bubble the original error).
export function decodeContractError(err: unknown): QuipError | null {
  return decoder.decodeContractError(err);
}

/// Decode raw revert bytes (selector + abi-encoded args) into a typed
/// `QuipError`. Returns `null` for empty/unrecognized payloads.
export function decodeRevertBytes(data: Hex): QuipError | null {
  return decoder.decodeRevertBytes(data);
}

/// Wrap a promise so any contract-revert error it throws is decoded into a typed
/// `QuipError`. Non-contract errors bubble unchanged.
export async function withDecodedError<T>(promise: Promise<T>): Promise<T> {
  return decoder.withDecodedError(promise);
}
