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

/// @deprecated WOTS+-family client errors — sunset with the WOTS+ wallet
/// family (superseded by SHRINCS, see `./v1/shrincs`).
///
/// Only the error classes thrown exclusively by the deprecated WOTS+ client
/// modules live here. Everything else — the `QuipError` base, the on-chain
/// error registry consumed by `internal/decodeError.ts`, and the shared
/// operational errors — stays in the live `src/v1/errors.ts` (shared runtime
/// infrastructure must never import from `deprecated/`), and is re-exported
/// below so this module preserves the full historical `./v1/errors` surface.
import { type Hex } from "viem";

import {
  type QuipErrorOptions,
  PaymasterValidationFailure,
  QuipError,
  UserOpValidationFailure,
} from "../../v1/errors.js";

export * from "../../v1/errors.js";

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
