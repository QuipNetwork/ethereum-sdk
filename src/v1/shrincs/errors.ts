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

// Shrincs SDK errors extend the shared `QuipError` base from the v1 SDK so that
// `instanceof QuipError` and the `.code` discriminator work uniformly across
// both wallet families. Contract-revert -> typed-error mapping lives in
// `internal/decodeError.ts`.
import { QuipError, type QuipErrorOptions } from "../errors.js";

// Re-export the base + the generic operational errors the reused helpers
// (`internal/providerState.ts`, `gas.ts`) already throw, so Shrincs callers can
// import everything from this barrel.
export {
  QuipError,
  type QuipErrorOptions,
  BalanceTooLowError,
  GasEstimationError,
  ChainChangedError,
  AccountChangedError,
  UnsupportedNetworkError,
} from "../errors.js";

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    VALIDATION ENUMS                         */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// `IShrincsWallet.UserOpValidationFailure` — the reason in a
/// `UserOpValidationRejected` event from ERC-4337 `validateUserOp`.
export enum UserOpValidationFailure {
  BadSignatureLength = 0,
  StaleStatefulLeaf = 1,
  StatefulBudgetExhausted = 2,
  InvalidSignature = 3,
}

/// `IShrincsWallet.Erc1271ValidationResult` — the diagnostic result from
/// `debugIsValidSignature`.
export enum Erc1271ValidationResult {
  Ok = 0,
  BadSignatureLength = 1,
  InvalidEcdsaSignature = 2,
  InvalidShrincsSignature = 3,
}

/// `IShrincsPaymaster.PaymasterValidationFailure` — the reason in a
/// `PaymasterValidationRejected` event from `validatePaymasterUserOp`.
export enum PaymasterValidationFailure {
  MalformedPayload = 0,
  StaleStatefulLeaf = 1,
  InvalidSignature = 2,
  StatefulBudgetExhausted = 3,
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                  SDK OPERATIONAL ERRORS                     */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// A freshly derived SHRINCS keypair failed its post-derivation self-test.
export class ShrincsKeyDerivationSelfTestError extends QuipError {
  readonly publicKeyCommitment: Hex;
  constructor(publicKeyCommitment: Hex, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_KEY_DERIVATION_SELFTEST_FAILED",
      `SHRINCS key with commitment ${publicKeyCommitment} failed the post-derivation self-test`,
      opts
    );
    this.publicKeyCommitment = publicKeyCommitment;
  }
}

/// The paymaster sponsorship key's commitment does not match the verifier
/// registered on chain — signing would be rejected. Caught client-side before
/// any signature is produced.
export class VerifierMismatchError extends QuipError {
  readonly suppliedCommitment: Hex;
  readonly onChainCommitment: Hex;
  constructor(
    suppliedCommitment: Hex,
    onChainCommitment: Hex,
    opts?: QuipErrorOptions
  ) {
    super(
      "SHRINCS_VERIFIER_MISMATCH",
      `Sponsorship key commitment ${suppliedCommitment} does not match the registered verifier ${onChainCommitment}`,
      opts
    );
    this.suppliedCommitment = suppliedCommitment;
    this.onChainCommitment = onChainCommitment;
  }
}

/// Fallback for a recognized contract revert with no dedicated SDK class.
export class UnknownContractError extends QuipError {
  readonly errorName?: string;
  readonly args?: readonly unknown[];
  constructor(
    errorName: string | undefined,
    args: readonly unknown[] | undefined,
    opts?: QuipErrorOptions
  ) {
    super(
      "UNKNOWN_CONTRACT_ERROR",
      errorName
        ? `Unrecognized contract error ${errorName}`
        : "Unrecognized contract revert",
      opts
    );
    this.errorName = errorName;
    this.args = args;
  }
}

/// `waitForTransactionReceipt` resolved with `status === "reverted"` — the
/// transaction landed but the call reverted on chain.
export class TransactionRevertedError extends QuipError {
  readonly transactionHash: Hex;
  constructor(transactionHash: Hex, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_TRANSACTION_REVERTED",
      `Transaction ${transactionHash} reverted`,
      opts
    );
    this.transactionHash = transactionHash;
  }
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                      WALLET ERRORS                          */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export class ZeroAddressFactoryError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_ZERO_ADDRESS_FACTORY", "Factory address is zero", opts);
  }
}

export class ZeroAddressOwnerError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_ZERO_ADDRESS_OWNER", "Owner address is zero", opts);
  }
}

export class ZeroAddressVerifierError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SHRINCS_ZERO_ADDRESS_VERIFIER",
      "SHRINCS verifier address is zero",
      opts
    );
  }
}

export class InvalidFactoryError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_INVALID_FACTORY", "Caller is not the wallet factory", opts);
  }
}

export class InvalidSignatureError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_INVALID_SIGNATURE", "SHRINCS signature verification failed", opts);
  }
}

export class CommitmentMismatchError extends QuipError {
  readonly suppliedCommitment?: Hex;
  readonly onChainCommitment?: Hex;
  constructor(
    suppliedCommitment?: Hex,
    onChainCommitment?: Hex,
    opts?: QuipErrorOptions
  ) {
    super(
      "SHRINCS_COMMITMENT_MISMATCH",
      suppliedCommitment && onChainCommitment
        ? `Signing key commitment ${suppliedCommitment} does not match the installed commitment ${onChainCommitment}`
        : "Supplied public key does not match the installed commitment",
      opts
    );
    this.suppliedCommitment = suppliedCommitment;
    this.onChainCommitment = onChainCommitment;
  }
}

export class ZeroErc1271CommitmentError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_ZERO_ERC1271_COMMITMENT", "ERC-1271 commitment is zero", opts);
  }
}

export class ZeroMaxSignaturesError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_ZERO_MAX_SIGNATURES", "maxSignatures is zero", opts);
  }
}

/// A declared hash suite other than `HASH_SUITE_KECCAK_256` was supplied at
/// install/rotate time (wallet initialize/migrate/setErc1271Key, paymaster
/// initialize).
export class UnsupportedHashSuiteError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SHRINCS_UNSUPPORTED_HASH_SUITE",
      "Hash suite is not HASH_SUITE_KECCAK_256 — the only suite the contracts accept",
      opts
    );
  }
}

/// The chosen stateful leaf has already been consumed in the current key epoch.
export class StaleStatefulLeafError extends QuipError {
  readonly leaf?: number;
  constructor(leaf?: number, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_STALE_STATEFUL_LEAF",
      leaf === undefined
        ? "Stateful leaf has already been consumed in the current key epoch"
        : `Stateful leaf ${leaf} has already been consumed in the current key epoch`,
      opts
    );
    this.leaf = leaf;
  }
}

/// An upgrade-auth blob bound an action nonce that no longer matches the live
/// one — the signed upgrade was superseded by a later consumed signature.
export class StaleActionNonceError extends QuipError {
  readonly expected?: bigint;
  readonly provided?: bigint;
  constructor(expected?: bigint, provided?: bigint, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_STALE_ACTION_NONCE",
      expected === undefined
        ? "Upgrade auth binds a stale action nonce; re-sign against the live actionNonce()"
        : `Upgrade auth binds stale action nonce ${provided ?? "?"} (live is ${expected}); re-sign against the live actionNonce()`,
      opts
    );
    this.expected = expected;
    this.provided = provided;
  }
}

/// No unused stateful leaf available in the current key epoch; rotate the key.
export class StatefulBudgetExhaustedError extends QuipError {
  readonly maxSignatures?: number;
  readonly used?: number;
  constructor(maxSignatures?: number, used?: number, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_STATEFUL_BUDGET_EXHAUSTED",
      maxSignatures === undefined
        ? "Stateful signature budget exhausted; rotate the key"
        : `No unused stateful leaf available (used ${used ?? "?"}/${maxSignatures}); rotate the key`,
      opts
    );
    this.maxSignatures = maxSignatures;
    this.used = used;
  }
}

/// `markLeavesUsed` was called with an empty target array. Burning the
/// authorizing leaf for nothing is almost certainly a mistake; a deliberate
/// single-leaf burn already exists via the empty `execute` path.
export class EmptyLeavesError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SHRINCS_EMPTY_LEAVES",
      "markLeavesUsed requires at least one target leaf",
      opts
    );
  }
}

/// A `markLeavesUsed` target leaf is zero or exceeds the installed key's
/// `maxSignatures` budget — a client bug, not a race, so the whole batch fails.
export class LeafOutOfRangeError extends QuipError {
  readonly leaf: number;
  readonly maxSignatures?: number;
  constructor(leaf: number, maxSignatures?: number, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_LEAF_OUT_OF_RANGE",
      maxSignatures === undefined
        ? `Revocation target leaf ${leaf} is out of range`
        : `Revocation target leaf ${leaf} is out of range (valid: 1..${maxSignatures})`,
      opts
    );
    this.leaf = leaf;
    this.maxSignatures = maxSignatures;
  }
}

/// Client-side only (never a contract revert): the explicitly-chosen authorizing
/// leaf is inside the revocation target set. A leaf being revoked has typically
/// already signed a message off-chain — authorizing with it would make its
/// one-time key sign a SECOND message, the exact key reuse `markLeavesUsed`
/// exists to prevent. Pick an authorizing leaf outside the target set (or omit
/// the override and let the client choose one).
export class AuthLeafInTargetsError extends QuipError {
  readonly leaf: number;
  constructor(leaf: number, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_AUTH_LEAF_IN_TARGETS",
      `Authorizing leaf ${leaf} is inside the revocation target set (OTS key-reuse hazard)`,
      opts
    );
    this.leaf = leaf;
  }
}

export class ImplementationNotVettedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SHRINCS_IMPLEMENTATION_NOT_VETTED",
      "Upgrade target is not in the factory's vetted-code set",
      opts
    );
  }
}

export class ImplementationDeprecatedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SHRINCS_IMPLEMENTATION_DEPRECATED",
      "Upgrade target implementation is deprecated",
      opts
    );
  }
}

export class NotUpgradingError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_NOT_UPGRADING", "migrate() called outside an upgrade context", opts);
  }
}

export class GuardedSlotTamperedError extends QuipError {
  readonly slotIndex: number;
  constructor(slotIndex: number, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_GUARDED_SLOT_TAMPERED",
      `Delegatecalled implementation modified guarded storage slot ${slotIndex}`,
      opts
    );
    this.slotIndex = slotIndex;
  }
}

export class MalformedCodecPayloadError extends QuipError {
  readonly expectedMin: bigint;
  readonly actual: bigint;
  constructor(expectedMin: bigint, actual: bigint, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_MALFORMED_PAYLOAD",
      `Malformed SHRINCS payload: expected at least ${expectedMin} bytes, got ${actual}`,
      opts
    );
    this.expectedMin = expectedMin;
    this.actual = actual;
  }
}

// ── disabled classical paths (thrown client-side and on revert) ──────────────

export class RenounceDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_RENOUNCE_DISABLED", "renounceOwnership is disabled on this wallet", opts);
  }
}

export class ClassicalWithdrawDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SHRINCS_CLASSICAL_WITHDRAW_DISABLED",
      "Classical withdrawDepositTo is disabled; use the SHRINCS-authorized path",
      opts
    );
  }
}

export class ClassicalTransferOwnershipDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SHRINCS_CLASSICAL_TRANSFER_OWNERSHIP_DISABLED",
      "Classical transferOwnership is disabled; use the SHRINCS-authorized handover",
      opts
    );
  }
}

export class OwnershipHandoverDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SHRINCS_OWNERSHIP_HANDOVER_DISABLED",
      "Solady ownership-handover flow is disabled on this wallet",
      opts
    );
  }
}

export class StorageStoreDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_STORAGE_STORE_DISABLED", "storageStore is disabled on this wallet", opts);
  }
}

export class DelegateExecuteDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_DELEGATE_EXECUTE_DISABLED", "delegateExecute is disabled on this wallet", opts);
  }
}

/// The factory's live execute fee exceeds the `maxFee` ceiling the signer
/// authorized. Only fee INCREASES past the cap trigger this — decreases charge
/// the lower live fee. Re-sign with a fresh (or higher) `maxFee`.
export class ExecuteFeeExceedsCapError extends QuipError {
  readonly fee?: bigint;
  readonly maxFee?: bigint;
  constructor(fee?: bigint, maxFee?: bigint, opts?: QuipErrorOptions) {
    super(
      "SHRINCS_EXECUTE_FEE_EXCEEDS_CAP",
      fee === undefined
        ? "Live execute fee exceeds the signed maxFee ceiling; re-sign with a fresh maxFee"
        : `Live execute fee ${fee} exceeds the signed maxFee ceiling ${maxFee ?? "?"}; re-sign with a fresh maxFee`,
      opts
    );
    this.fee = fee;
    this.maxFee = maxFee;
  }
}

/// The inherited un-capped `execute`/`executeBatch` selector was called; only
/// the `maxFee`-capped variants exist on this wallet.
export class StandardExecuteDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SHRINCS_STANDARD_EXECUTE_DISABLED",
      "The un-capped execute/executeBatch selectors are disabled; use the maxFee-capped variants",
      opts
    );
  }
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    PAYMASTER ERRORS                         */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export class InvalidEntryPointError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_INVALID_ENTRYPOINT", "Caller is not the EntryPoint", opts);
  }
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                  GENERIC (solady/oz)                        */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export class UnauthorizedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_UNAUTHORIZED", "Caller is not authorized", opts);
  }
}

export class AlreadyInitializedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("SHRINCS_ALREADY_INITIALIZED", "Contract is already initialized", opts);
  }
}
