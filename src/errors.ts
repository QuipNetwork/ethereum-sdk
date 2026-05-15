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
import type { Hex } from "viem";

export interface QuipErrorOptions {
  cause?: unknown;
  /// 4-byte error selector when the error originated from a contract revert.
  selector?: Hex;
  /// Raw revert data, when available.
  data?: Hex;
}

/// Base class for every SDK error. Carries a stable `code` for switch-style
/// branching, an optional `cause` (preserves the original error chain), and
/// the on-chain `selector`/`data` when the error originated from a contract
/// revert.
export class QuipError extends Error {
  readonly code: string;
  readonly cause?: unknown;
  readonly selector?: Hex;
  readonly data?: Hex;

  constructor(code: string, message: string, opts?: QuipErrorOptions) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    if (opts?.cause !== undefined) this.cause = opts.cause;
    if (opts?.selector) this.selector = opts.selector;
    if (opts?.data) this.data = opts.data;
  }
}

export class ZeroAddressFactoryError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("ZERO_ADDRESS_FACTORY", "Factory address is zero", opts);
  }
}

export class ZeroAddressOwnerError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("ZERO_ADDRESS_OWNER", "Owner address is zero", opts);
  }
}

export class InvalidFactoryError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("INVALID_FACTORY", "Caller is not the registered factory", opts);
  }
}

export class InvalidSignatureError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "INVALID_SIGNATURE",
      "WOTS+ signature did not verify against the expected transaction / recovery / ownership / disaster-recovery key",
      opts
    );
  }
}

export class RenounceDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "RENOUNCE_DISABLED",
      "Ownership renouncement is permanently disabled",
      opts
    );
  }
}

export class ClassicalWithdrawDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "CLASSICAL_WITHDRAW_DISABLED",
      "Classical-side withdraw is disabled; use the PQ-authorized path",
      opts
    );
  }
}

export class ClassicalTransferOwnershipDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "CLASSICAL_TRANSFER_OWNERSHIP_DISABLED",
      "Classical-side transferOwnership is disabled",
      opts
    );
  }
}

export class ClassicalCompleteOwnershipHandoverDisabledError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "CLASSICAL_COMPLETE_OWNERSHIP_HANDOVER_DISABLED",
      "Classical-side completeOwnershipHandover is disabled",
      opts
    );
  }
}

export class DuplicateKeyError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("DUPLICATE_KEY", "Key is already present in the keyset", opts);
  }
}

export class KeyInUseError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("KEY_IN_USE", "Key collides with another live keyset entry", opts);
  }
}

export class SameKeyError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "SAME_KEY",
      "Next key is identical to the current key; WOTS+ rotation requires a distinct replacement",
      opts
    );
  }
}

export class UnknownKeyError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("UNKNOWN_KEY", "Key is not present in the expected keyset", opts);
  }
}

export class KeyAdditionFailedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "KEY_ADDITION_FAILED",
      "Underlying keyset rejected the addition (capacity or duplicate)",
      opts
    );
  }
}

export class KeyRemovalFailedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "KEY_REMOVAL_FAILED",
      "Underlying keyset rejected the removal (key not present)",
      opts
    );
  }
}

export class EmptyKeysError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("EMPTY_KEYS", "No keys supplied for the operation", opts);
  }
}

export class RefreshTransactionForbiddenError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "REFRESH_TRANSACTION_FORBIDDEN",
      "Refreshing the transaction keyset is forbidden",
      opts
    );
  }
}

export class IncorrectRecoveryKeyAmountError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "INCORRECT_RECOVERY_KEY_AMOUNT",
      "Recovery keyset must contain exactly MAX_RECOVERY_KEYS keys",
      opts
    );
  }
}

export class ReplaceAuthKeyForbiddenError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "REPLACE_AUTH_KEY_FORBIDDEN",
      "Replacing the authoritative key via replaceKeyAt is forbidden",
      opts
    );
  }
}

export class ReinstallSpentKeyForbiddenError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "REINSTALL_SPENT_KEY_FORBIDDEN",
      "Cannot reinstall a previously consumed key",
      opts
    );
  }
}

export class NotUpgradingError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "NOT_UPGRADING",
      "migrate() called outside an active upgradeToAndCall context",
      opts
    );
  }
}

export class IncorrectTransactionKeyAmountError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "INCORRECT_TRANSACTION_KEY_AMOUNT",
      "Transaction key payload size disagrees with the expected init amount",
      opts
    );
  }
}

export class ImplementationNotVettedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "IMPLEMENTATION_NOT_VETTED",
      "Target implementation is not vetted by the factory",
      opts
    );
  }
}

export class ImplementationDeprecatedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "IMPLEMENTATION_DEPRECATED",
      "Target implementation has been deprecated",
      opts
    );
  }
}

export class UnknownDisasterRecoveryKeyError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "UNKNOWN_DISASTER_RECOVERY_KEY",
      "Provided disaster recovery key does not match the wallet's stored disasterRecoveryKey slot",
      opts
    );
  }
}

export class UnknownOwnershipKeyError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "UNKNOWN_OWNERSHIP_KEY",
      "Provided ownership key does not match the wallet's stored ownershipKey slot",
      opts
    );
  }
}

export class GuardedSlotTamperedError extends QuipError {
  /// 0-based index of the guarded slot that was tampered with during a
  /// delegateExecute.
  readonly slotIndex: number;

  constructor(slotIndex: number, opts?: QuipErrorOptions) {
    super(
      "GUARDED_SLOT_TAMPERED",
      `Guarded storage slot ${slotIndex} was modified during delegateExecute`,
      opts
    );
    this.slotIndex = slotIndex;
  }
}

export class GuardedSlotWriteDeniedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "GUARDED_SLOT_WRITE_DENIED",
      "storageStore attempted to write a guarded slot",
      opts
    );
  }
}

export class InsufficientBalanceError extends QuipError {
  readonly requested: bigint;
  readonly available: bigint;

  constructor(requested: bigint, available: bigint, opts?: QuipErrorOptions) {
    super(
      "INSUFFICIENT_BALANCE",
      `Insufficient balance: requested ${requested.toString()}, available ${available.toString()}`,
      opts
    );
    this.requested = requested;
    this.available = available;
  }
}

export class FeeExceedsMaxError extends QuipError {
  readonly fee: bigint;
  readonly maxFee: bigint;

  constructor(fee: bigint, maxFee: bigint, opts?: QuipErrorOptions) {
    super(
      "FEE_EXCEEDS_MAX",
      `Fee ${fee.toString()} exceeds maximum ${maxFee.toString()}`,
      opts
    );
    this.fee = fee;
    this.maxFee = maxFee;
  }
}

export class EmptyCodeError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super("EMPTY_CODE", "Implementation address has no deployed code", opts);
  }
}

export class AlreadyVettedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "ALREADY_VETTED",
      "Implementation codehash is already in the vetted set",
      opts
    );
  }
}

export class NotDeprecatedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "NOT_DEPRECATED",
      "Implementation is not currently flagged as deprecated",
      opts
    );
  }
}

export class NoActiveImplementationError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "NO_ACTIVE_IMPLEMENTATION",
      "Factory has no current active implementation set",
      opts
    );
  }
}

export class InsufficientCreationFeeError extends QuipError {
  readonly sent: bigint;
  readonly required: bigint;

  constructor(sent: bigint, required: bigint, opts?: QuipErrorOptions) {
    super(
      "INSUFFICIENT_CREATION_FEE",
      `Insufficient creation fee: sent ${sent.toString()}, required ${required.toString()}`,
      opts
    );
    this.sent = sent;
    this.required = required;
  }
}

export class ZeroMaxFeeError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "ZERO_MAX_FEE",
      "Factory cannot be deployed with MAX_FEE = 0",
      opts
    );
  }
}

export class InvalidEntryPointError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "INVALID_ENTRY_POINT",
      "Caller is not the canonical ERC-4337 EntryPoint",
      opts
    );
  }
}

export class ZeroValuePqVerifierKeyError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "ZERO_VALUE_PQ_VERIFIER_KEY",
      "PQ verifier key has zero publicSeed or publicKeyHash",
      opts
    );
  }
}

export class PqVerifierNotRegisteredError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "PQ_VERIFIER_NOT_REGISTERED",
      "Wallet has no PQ verifier registered with the paymaster",
      opts
    );
  }
}

export class VerifierKeyInUseError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "VERIFIER_KEY_IN_USE",
      "PQ verifier key is already bound to another wallet",
      opts
    );
  }
}

/// Mirrors `IQuipWallet.UserOpValidationFailure`.
export enum UserOpValidationFailure {
  ZeroNextKey = 0,
  StaleCurrentKey = 1,
  NextKeyAlreadyInUse = 2,
  InvalidSignature = 3,
}

/// Mirrors `IQuipPaymaster.PaymasterValidationFailure`.
export enum PaymasterValidationFailure {
  MalformedPayload = 0,
  ZeroNextVerifier = 1,
  NoVerifierRegistered = 2,
  NextEqualsCurrent = 3,
  NextVerifierKeyInUse = 4,
  InvalidSignature = 5,
}

/// Mirrors `IQuipWallet.Erc1271ValidationResult`.
export enum Erc1271ValidationResult {
  Ok = 0,
  BadSignatureLength = 1,
  InvalidEcdsaSignature = 2,
  UnknownVerifier = 3,
  InvalidPqSignature = 4,
}

/// Surfaced from simulation traces (UserOpValidationRejected event) since
/// `validateUserOp` cannot revert with a reason per ERC-4337.
export class Erc4337WalletValidationError extends QuipError {
  readonly reason: UserOpValidationFailure;

  constructor(reason: UserOpValidationFailure, opts?: QuipErrorOptions) {
    super(
      "ERC4337_WALLET_VALIDATION",
      `Wallet ERC-4337 validation rejected: ${UserOpValidationFailure[reason]}`,
      opts
    );
    this.reason = reason;
  }
}

/// Surfaced from simulation traces (PaymasterValidationRejected event).
export class Erc4337PaymasterValidationError extends QuipError {
  readonly reason: PaymasterValidationFailure;

  constructor(reason: PaymasterValidationFailure, opts?: QuipErrorOptions) {
    super(
      "ERC4337_PAYMASTER_VALIDATION",
      `Paymaster ERC-4337 validation rejected: ${PaymasterValidationFailure[reason]}`,
      opts
    );
    this.reason = reason;
  }
}

/// Thrown when a method is called on a `QuipClient` whose async
/// initialization has not resolved.
export class WalletNotInitializedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "WALLET_NOT_INITIALIZED",
      "Client not initialized. Call await client.initializationPromise (or use QuipClient.create) first.",
      opts
    );
  }
}

export class WalletAlreadyExistsError extends QuipError {
  readonly vaultId: Hex;

  constructor(vaultId: Hex, opts?: QuipErrorOptions) {
    super(
      "WALLET_ALREADY_EXISTS",
      `Wallet already exists for vault ID ${vaultId}`,
      opts
    );
    this.vaultId = vaultId;
  }
}

export class NoVaultFoundError extends QuipError {
  readonly vaultId: Hex;

  constructor(vaultId: Hex, opts?: QuipErrorOptions) {
    super(
      "NO_VAULT_FOUND",
      `No wallet found for vault ID ${vaultId}`,
      opts
    );
    this.vaultId = vaultId;
  }
}

export class InvalidSignerError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "INVALID_SIGNER",
      "Provided QuipSigner could not regenerate the wallet's current head transaction key",
      opts
    );
  }
}

export class NotConnectedError extends QuipError {
  constructor(opts?: QuipErrorOptions) {
    super(
      "NOT_CONNECTED",
      "No account available. Connect a wallet first.",
      opts
    );
  }
}

export class UnsupportedNetworkError extends QuipError {
  readonly chainId: number;

  constructor(chainId: number, opts?: QuipErrorOptions) {
    super(
      "UNSUPPORTED_NETWORK",
      `Chain id ${chainId} is not supported by this SDK build`,
      opts
    );
    this.chainId = chainId;
  }
}

export class MulticallUnavailableError extends QuipError {
  readonly chainId: number;

  constructor(chainId: number, opts?: QuipErrorOptions) {
    super(
      "MULTICALL_UNAVAILABLE",
      `Multicall3 is not deployed on chain id ${chainId}; falling back to sequential reads`,
      opts
    );
    this.chainId = chainId;
  }
}

export class GasEstimationError extends QuipError {
  constructor(message: string, opts?: QuipErrorOptions) {
    super("GAS_ESTIMATION_FAILED", message, opts);
  }
}

export class BalanceTooLowError extends QuipError {
  readonly required: bigint;
  readonly available: bigint;

  constructor(required: bigint, available: bigint, opts?: QuipErrorOptions) {
    super(
      "BALANCE_TOO_LOW",
      `Wallet balance ${available.toString()} insufficient for required ${required.toString()}`,
      opts
    );
    this.required = required;
    this.available = available;
  }
}

/// Thrown by a `ConsumeKeyFn` (and surfaced through `QuipSigner.sign`) when
/// a key has already been used to sign a previously-broadcast payload. WOTS+
/// is a one-time signature scheme — once a signature is publicly visible, the
/// key is compromised and reuse leaks secret material.
///
/// Lives in `errors.ts` rather than `burnSet.ts` because callers writing
/// their own `ConsumeKeyFn` (e.g. against a sqlite/redis backend) are
/// expected to import and throw this class for consistency with the
/// in-memory default. The SDK does not throw it directly — the injected
/// `consume` function does, inside `QuipSigner.sign(...)`.
///
/// Retry semantics: if a write reverts, retry MUST use a different
/// transaction key via `signWithKey`. See `SDK_README.md` for the full
/// operational contract.
export class KeyAlreadyBurnedError extends QuipError {
  readonly publicSeed: Hex;

  constructor(publicSeed: Hex, opts?: QuipErrorOptions) {
    super(
      "KEY_ALREADY_BURNED",
      "WOTS+ key has already been used to sign a broadcast payload; retry with a different key via signWithKey",
      opts
    );
    this.publicSeed = publicSeed;
  }
}

/// Thrown by `QuipSigner.generateKeyPair` / `recoverKeyPair` when the
/// post-derivation self-test (sign + verify against a fixed sentinel digest)
/// fails. Catches WOTS+ library bugs, memory corruption, and derivation
/// drift before the keypair is ever used to sign a real payload. The
/// sentinel signature is produced locally, never returned, and never
/// recorded against the burn set.
export class KeyDerivationSelfTestError extends QuipError {
  readonly publicSeed: Hex;

  constructor(publicSeed: Hex, opts?: QuipErrorOptions) {
    super(
      "KEY_DERIVATION_SELFTEST_FAILED",
      `WOTS+ key with publicSeed ${publicSeed} failed the post-derivation self-test (sign + verify against the sentinel digest did not round-trip)`,
      opts
    );
    this.publicSeed = publicSeed;
  }
}

/// Thrown when `tryMulticall` returns one or more failed sub-calls in a
/// context where the caller cannot reasonably proceed with partial results
/// (e.g. `getWalletState`, `getKeyset`, `getFactoryState`). Carries the
/// labels of the failed calls and the underlying errors so the caller can
/// diagnose without re-running the multicall.
export class PartialMulticallResultError extends QuipError {
  readonly failures: ReadonlyArray<{ label: string; error: Error }>;

  constructor(
    failures: ReadonlyArray<{ label: string; error: Error }>,
    opts?: QuipErrorOptions
  ) {
    const summary = failures.map((f) => f.label).join(", ");
    super(
      "PARTIAL_MULTICALL_RESULT",
      `Multicall returned partial results; failed calls: ${summary}`,
      opts
    );
    this.failures = failures;
  }
}

/// Fallback for a contract revert whose selector did not match any known
/// error in our combined ABI. Preserves whatever viem could decode.
export class UnknownContractError extends QuipError {
  readonly errorName?: string;
  readonly args?: readonly unknown[];

  constructor(
    errorName: string | undefined,
    args: readonly unknown[] | undefined,
    opts?: QuipErrorOptions
  ) {
    const label = errorName ? `${errorName}(${(args ?? []).join(", ")})` : "unknown";
    super("UNKNOWN_CONTRACT_ERROR", `Unrecognized contract revert: ${label}`, opts);
    if (errorName) this.errorName = errorName;
    if (args) this.args = args;
  }
}
