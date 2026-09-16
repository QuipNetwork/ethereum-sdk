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
import { type Address, type Hex, concat, keccak256, toHex } from "viem";

// The ERC-4337 v0.7 userOp plumbing (packed type, gas-limit packing, the
// canonical userOpHash) is signature-scheme-agnostic, so the Shrincs SDK reuses
// the v1 implementations rather than duplicating them.
import {
  type PackedUserOperation,
  computeUserOpHash,
  packAccountGasLimits,
  packGasFees,
} from "../userOpCodec.js";
import {
  ACTION_ERC4337_EXECUTE,
  ACTION_PAYMASTER_APPROVE,
  PAYMASTER_DOMAIN_TAG,
  buildActionContext,
  domainSeparator,
  encodeSponsorshipSignature,
  encodeUserOpSignature,
  erc4337PayloadHash,
} from "./shrincsCodec.js";
import {
  DEFAULT_CALL_GAS_LIMIT,
  DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
  DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
  DEFAULT_PRE_VERIFICATION_GAS,
  DEFAULT_SPONSORSHIP_VALIDITY_SECONDS,
  DEFAULT_VERIFICATION_GAS_LIMIT,
  MAX_PAYMASTER_TIMESTAMP,
} from "./constants.js";
import { InvalidSponsorshipWindowError } from "./errors.js";
import { type ShrincsKeyPair } from "./shrincsSigner.js";
import { type ShrincsPublicKey, type StatefulSignature } from "./types.js";

export { type PackedUserOperation, computeUserOpHash } from "../userOpCodec.js";
export { PAYMASTER_DOMAIN_TAG, ACTION_PAYMASTER_APPROVE };

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                      USEROP BUILDING                        */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export interface BuildUserOpParams {
  sender: Address;
  nonce: bigint;
  callData: Hex;
  initCode?: Hex;
  verificationGasLimit?: bigint;
  callGasLimit?: bigint;
  preVerificationGas?: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  paymasterAndData?: Hex;
}

/// Assemble a `PackedUserOperation`, falling back to conservative gas defaults.
/// `signature` is left `0x` for the caller to fill via `signWalletUserOp`.
export function buildUserOp(params: BuildUserOpParams): PackedUserOperation {
  return {
    sender: params.sender,
    nonce: params.nonce,
    initCode: params.initCode ?? "0x",
    callData: params.callData,
    accountGasLimits: packAccountGasLimits(
      params.verificationGasLimit ?? DEFAULT_VERIFICATION_GAS_LIMIT,
      params.callGasLimit ?? DEFAULT_CALL_GAS_LIMIT
    ),
    preVerificationGas: params.preVerificationGas ?? DEFAULT_PRE_VERIFICATION_GAS,
    gasFees: packGasFees(params.maxPriorityFeePerGas, params.maxFeePerGas),
    paymasterAndData: params.paymasterAndData ?? "0x",
    signature: "0x",
  };
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    WALLET USEROP SIGNING                    */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export interface SignWalletUserOpParams {
  keypair: ShrincsKeyPair;
  userOp: PackedUserOperation;
  entryPoint: Address;
  chainId: bigint;
  wallet: Address;
  keyVersion: bigint;
  /// Lowest unused stateful leaf, read from the on-chain bitmap by the client.
  leaf: number;
  /// The wallet's live `actionNonce()`. Every consumed signature advances it,
  /// so ops must land in signing order — signing a second op before the first
  /// lands binds a stale nonce and it will be rejected (AA24).
  actionNonce: bigint;
  /// The owner's ECDSA co-signature over the wallet's
  /// `quipUserOpHashEcdsaTarget(userOpHash)` EIP-712 digest, where `userOpHash`
  /// is `computeUserOpHash(userOp, entryPoint, chainId)`. Every userOp is
  /// hybrid: `_validateSignature` requires this to recover `owner()` BEFORE the
  /// SHRINCS verify. `ShrincsWalletClient.signExecuteUserOp` produces it via
  /// the on-chain target getter; callers using this function directly must sign
  /// the same digest.
  ownerEcdsaSig: Hex;
}

export interface SignedWalletUserOp {
  /// Ready to substitute into `userOp.signature`.
  signature: Hex;
  userOpHash: Hex;
}

/// Sign a wallet ERC-4337 userOp: bind the EntryPoint `userOpHash` into the
/// canonical `ACTION_ERC4337_EXECUTE` action, sign at `leaf`, and ABI pack
/// `(PublicKey, StatefulSignature, bytes ecdsaSig)` into the signature field —
/// the SHRINCS half plus the owner's co-signature (hybrid gate). No fee is
/// bound here: the signer's `maxFee` ceiling is a calldata parameter of the
/// capped `execute`/`executeBatch` variants, covered by `userOpHash` via
/// `callData` (ERC-7562: validation reads no fee).
export function signWalletUserOp(
  params: SignWalletUserOpParams
): SignedWalletUserOp {
  const userOpHash = computeUserOpHash(params.userOp, params.entryPoint, params.chainId);
  const ctx = buildActionContext({
    domainSeparator: domainSeparator(params.chainId, params.wallet),
    nonce: params.actionNonce,
    keyVersion: params.keyVersion,
    actionType: ACTION_ERC4337_EXECUTE,
    payloadHash: erc4337PayloadHash(userOpHash),
  });
  const signature = params.keypair.signStatefulActionAt(ctx, params.leaf);
  return {
    signature: encodeUserOpSignature(
      params.keypair.publicKey,
      signature,
      params.ownerEcdsaSig
    ),
    userOpHash,
  };
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                  PAYMASTER SPONSORSHIP                      */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// `paymasterAndData[0:64)` header (mirrors the ERC-4337 v0.7 prefix + the
/// Shrincs custom validUntil/validAfter region). The sponsorship binding hash
/// covers exactly this slice (the SHRINCS blob at `[64:)` is excluded).
export function packPaymasterHeader(params: {
  paymaster: Address;
  verificationGasLimit: bigint;
  postOpGasLimit: bigint;
  validUntil: number;
  validAfter: number;
}): Hex {
  return concat([
    params.paymaster,
    toHex(params.verificationGasLimit, { size: 16 }),
    toHex(params.postOpGasLimit, { size: 16 }),
    toHex(params.validUntil, { size: 6 }),
    toHex(params.validAfter, { size: 6 }),
  ]);
}

/// `_userOpBindingHash` from `ShrincsPaymaster.sol`: the userOp field set with
/// `paymasterAndData` truncated to its 64-byte header (the SHRINCS signature
/// region is excluded to break the circular dependency).
export function paymasterBindingHash(
  userOp: PackedUserOperation,
  header64: Hex
): Hex {
  return keccak256(
    concat([
      toHex(BigInt(userOp.sender), { size: 32 }),
      toHex(userOp.nonce, { size: 32 }),
      keccak256(userOp.initCode),
      keccak256(userOp.callData),
      userOp.accountGasLimits,
      toHex(userOp.preVerificationGas, { size: 32 }),
      userOp.gasFees,
      keccak256(header64),
    ])
  );
}

export function packPaymasterAndData(params: {
  header64: Hex;
  publicKey: ShrincsPublicKey;
  signature: StatefulSignature;
}): Hex {
  // The sponsorship blob keeps the plain (PublicKey, StatefulSignature) pair —
  // no ECDSA co-signer on the paymaster's global key.
  return concat([
    params.header64,
    encodeSponsorshipSignature(params.publicKey, params.signature),
  ]);
}

export interface SignPaymasterUserOpParams {
  keypair: ShrincsKeyPair;
  userOp: PackedUserOperation;
  paymaster: Address;
  chainId: bigint;
  keyVersion: bigint;
  verificationGasLimit?: bigint;
  postOpGasLimit?: bigint;
  /// Unix seconds after which the EntryPoint rejects the sponsorship. Omitted:
  /// `now + validitySeconds`. `0` is the ERC-4337 sentinel for NO expiry and
  /// must be passed explicitly — an unbounded approval is never the default.
  validUntil?: number;
  /// Unix seconds before which the EntryPoint rejects the sponsorship. Default 0.
  validAfter?: number;
  /// Lifetime used when `validUntil` is omitted. Default
  /// `DEFAULT_SPONSORSHIP_VALIDITY_SECONDS` (15 minutes).
  validitySeconds?: number;
  /// The clock (unix seconds) the default `validUntil` and the expiry check are
  /// computed against. Default: the local wall clock.
  now?: number;
  /// Lowest unused stateful leaf on the paymaster, read from chain by the client.
  leaf: number;
}

/// Resolve and validate a sponsorship's validity window. Exposed so callers can
/// preview what `signPaymasterUserOp` will pack (and fail early) without
/// spending a leaf. Throws `InvalidSponsorshipWindowError` on an inverted,
/// already-expired, negative, non-integer or over-width window.
export function resolveSponsorshipWindow(params: {
  validUntil?: number;
  validAfter?: number;
  validitySeconds?: number;
  now?: number;
}): { validUntil: number; validAfter: number; now: number } {
  const now = params.now ?? Math.floor(Date.now() / 1000);
  const validAfter = params.validAfter ?? 0;
  const validitySeconds = params.validitySeconds ?? DEFAULT_SPONSORSHIP_VALIDITY_SECONDS;
  if (!Number.isInteger(validitySeconds) || validitySeconds <= 0) {
    throw new InvalidSponsorshipWindowError(
      params.validUntil ?? -1,
      validAfter,
      `validitySeconds must be a positive integer, got ${validitySeconds}`
    );
  }
  const validUntil = params.validUntil ?? now + validitySeconds;
  const fail = (reason: string): never => {
    throw new InvalidSponsorshipWindowError(validUntil, validAfter, reason);
  };
  for (const [name, value] of [
    ["validUntil", validUntil],
    ["validAfter", validAfter],
  ] as const) {
    if (!Number.isInteger(value) || value < 0) fail(`${name} must be a non-negative integer`);
    if (value > MAX_PAYMASTER_TIMESTAMP) fail(`${name} exceeds the 6-byte field (max ${MAX_PAYMASTER_TIMESTAMP})`);
  }
  if (validUntil !== 0) {
    if (validUntil <= validAfter) fail("validUntil must be after validAfter (or 0 for no expiry)");
    if (validUntil <= now) fail(`validUntil is already in the past at signing time (now=${now})`);
  }
  return { validUntil, validAfter, now };
}

/// Produce the fully-signed `paymasterAndData` for a sponsored userOp. Binds the
/// sponsorship to the specific wallet via the userOp's `sender`, so one global
/// verifier key safely covers all wallets. The validity window is resolved by
/// `resolveSponsorshipWindow` BEFORE the leaf is signed: a malformed window
/// throws rather than burning a one-time leaf on an unusable approval.
export function signPaymasterUserOp(params: SignPaymasterUserOpParams): Hex {
  const { validUntil, validAfter } = resolveSponsorshipWindow(params);
  const header64 = packPaymasterHeader({
    paymaster: params.paymaster,
    verificationGasLimit:
      params.verificationGasLimit ?? DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
    postOpGasLimit: params.postOpGasLimit ?? DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
    validUntil,
    validAfter,
  });
  // The binding covers the header (which is `paymasterAndData[0:64)` at verify
  // time), so feed the header in as the truncated paymasterAndData.
  const bindingHash = paymasterBindingHash(params.userOp, header64);
  const ctx = buildActionContext({
    domainSeparator: domainSeparator(params.chainId, params.paymaster, PAYMASTER_DOMAIN_TAG),
    // The ShrincsPaymaster binds no wrapper nonce: its sponsorship freshness is
    // the validUntil/validAfter window plus its own one-time leaf.
    nonce: 0n,
    keyVersion: params.keyVersion,
    actionType: ACTION_PAYMASTER_APPROVE,
    payloadHash: bindingHash,
  });
  const signature = params.keypair.signStatefulActionAt(ctx, params.leaf);
  return packPaymasterAndData({
    header64,
    publicKey: params.keypair.publicKey,
    signature,
  });
}
