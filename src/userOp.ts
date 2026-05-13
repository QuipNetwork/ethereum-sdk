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
  type Hex,
  concat,
  encodeAbiParameters,
  hexToBytes,
  keccak256,
  pad,
  toHex,
} from "viem";

import { QuipSigner } from "./signer.js";
import {
  type WinternitzAddress as CodecAddress,
  type WinternitzElements,
  encodeUserOpSignature,
  erc4337ExecuteDigest,
  paymasterUserOpDigest as codecPaymasterUserOpDigest,
} from "./wotsCodec.js";

/// ERC-4337 v0.7 PackedUserOperation. Matches Solady's `ERC4337.sol:34` and
/// the canonical EntryPoint v0.7 layout. The two packed fields use the
/// EntryPoint v0.7 convention:
///   - `accountGasLimits` = `verificationGasLimit (uint128) || callGasLimit (uint128)`
///   - `gasFees`          = `maxPriorityFeePerGas (uint128) || maxFeePerGas (uint128)`
/// (high bytes first in each case)
export interface PackedUserOperation {
  sender: Address;
  nonce: bigint;
  initCode: Hex;
  callData: Hex;
  accountGasLimits: Hex; // bytes32
  preVerificationGas: bigint;
  gasFees: Hex; // bytes32
  paymasterAndData: Hex;
  signature: Hex;
}

/// Conservative default gas budgets. Real values should come from the
/// state-override gas-estimation path in `QuipWalletClient.buildExecuteUserOp`;
/// these are the fallback when the caller skips estimation.
export const DEFAULT_VERIFICATION_GAS_LIMIT: bigint = 1_500_000n;
export const DEFAULT_CALL_GAS_LIMIT: bigint = 500_000n;
export const DEFAULT_PRE_VERIFICATION_GAS: bigint = 80_000n;

/// Pack two uint128 values into a bytes32 with the high 16 bytes being
/// `hi` and the low 16 bytes being `lo`. EntryPoint v0.7 uses this for
/// both `accountGasLimits` and `gasFees`.
export function packUint128Pair(hi: bigint, lo: bigint): Hex {
  if (hi < 0n || hi >= 1n << 128n) {
    throw new Error(`packUint128Pair: high value out of range: ${hi}`);
  }
  if (lo < 0n || lo >= 1n << 128n) {
    throw new Error(`packUint128Pair: low value out of range: ${lo}`);
  }
  const packed = (hi << 128n) | lo;
  return pad(toHex(packed), { size: 32 });
}

/// Convenience: pack (verificationGasLimit, callGasLimit) for `accountGasLimits`.
export function packAccountGasLimits(
  verificationGasLimit: bigint,
  callGasLimit: bigint
): Hex {
  return packUint128Pair(verificationGasLimit, callGasLimit);
}

/// Convenience: pack (maxPriorityFeePerGas, maxFeePerGas) for `gasFees`.
export function packGasFees(
  maxPriorityFeePerGas: bigint,
  maxFeePerGas: bigint
): Hex {
  return packUint128Pair(maxPriorityFeePerGas, maxFeePerGas);
}

export interface BuildUserOpParams {
  sender: Address;
  nonce: bigint;
  callData: Hex;
  /// Default: 0x (already-deployed account, no init).
  initCode?: Hex;
  /// Default: 0x (no sponsorship).
  paymasterAndData?: Hex;
  /// Default: 0x (caller signs after).
  signature?: Hex;
  verificationGasLimit?: bigint;
  callGasLimit?: bigint;
  preVerificationGas?: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
}

/// Construct a `PackedUserOperation` from caller-supplied fields. Gas
/// budgets fall back to `DEFAULT_*` constants when unspecified; fee fields
/// are required (the caller knows the chain's fee market). The returned
/// UserOp's `signature` defaults to `0x` — sign by computing
/// `walletUserOpDigest` and assembling via `packWalletSignature`, then
/// substituting `signature` on the returned struct (or use
/// `signWalletUserOp` for the combined flow).
export function buildUserOp(params: BuildUserOpParams): PackedUserOperation {
  const verificationGasLimit =
    params.verificationGasLimit ?? DEFAULT_VERIFICATION_GAS_LIMIT;
  const callGasLimit = params.callGasLimit ?? DEFAULT_CALL_GAS_LIMIT;
  const preVerificationGas =
    params.preVerificationGas ?? DEFAULT_PRE_VERIFICATION_GAS;

  return {
    sender: params.sender,
    nonce: params.nonce,
    initCode: params.initCode ?? "0x",
    callData: params.callData,
    accountGasLimits: packAccountGasLimits(verificationGasLimit, callGasLimit),
    preVerificationGas,
    gasFees: packGasFees(params.maxPriorityFeePerGas, params.maxFeePerGas),
    paymasterAndData: params.paymasterAndData ?? "0x",
    signature: params.signature ?? "0x",
  };
}

/// Compute the EntryPoint v0.7 `userOpHash` locally — no RPC roundtrip.
/// Matches the reference implementation at
/// https://github.com/eth-infinitism/account-abstraction/blob/v0.7/contracts/core/UserOperationLib.sol
///
///     keccak256(abi.encode(hashUserOp(userOp), entryPoint, chainId))
///
/// where
///
///     hashUserOp(userOp) =
///       keccak256(abi.encode(
///         sender, nonce,
///         keccak256(initCode),
///         keccak256(callData),
///         accountGasLimits,
///         preVerificationGas,
///         gasFees,
///         keccak256(paymasterAndData)
///       ))
///
/// `signature` is excluded by design — it's what we're about to produce.
export function computeUserOpHash(
  userOp: PackedUserOperation,
  entryPoint: Address,
  chainId: bigint
): Hex {
  const inner = keccak256(
    encodeAbiParameters(
      [
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [
        userOp.sender,
        userOp.nonce,
        keccak256(userOp.initCode),
        keccak256(userOp.callData),
        userOp.accountGasLimits,
        userOp.preVerificationGas,
        userOp.gasFees,
        keccak256(userOp.paymasterAndData),
      ]
    )
  );
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "uint256" }],
      [inner, entryPoint, chainId]
    )
  );
}

/// Wallet-side digest for the WOTS+ signature. Wraps the EntryPoint's
/// `userOpHash` with the rotating-key fields the wallet enforces, per
/// `Codec.erc4337ExecuteDigest` in `QuipWallet._validateSignature`.
export function walletUserOpDigest(params: {
  wallet: Address;
  chainId: bigint;
  currentKey: CodecAddress;
  nextKey: CodecAddress;
  userOpHash: Hex;
  executeFee: bigint;
}): Hex {
  return erc4337ExecuteDigest(
    params.wallet,
    params.chainId,
    params.currentKey.publicSeed,
    params.currentKey.publicKeyHash,
    params.nextKey.publicSeed,
    params.nextKey.publicKeyHash,
    params.userOpHash,
    params.executeFee
  );
}

/// Assemble the `signature` field of a wallet-validated UserOp. Mirrors
/// `Codec.decodeUserOpSignature` on the contract side — the wallet's
/// `_validateSignature` parses exactly this layout.
export function packWalletSignature(
  currentKey: CodecAddress,
  nextKey: CodecAddress,
  pqSig: WinternitzElements
): Hex {
  return encodeUserOpSignature(currentKey, nextKey, pqSig);
}

/// Sign a UserOp with a WOTS+ key. Computes the EntryPoint userOpHash,
/// wraps it in the wallet-side digest, signs via `QuipSigner`, and returns
/// the assembled signature bytes. Caller substitutes this into
/// `userOp.signature` before submitting to the EntryPoint.
///
/// The signing key is the WOTS+ keypair derived from `(vaultId, currentKey.publicSeed)`.
/// Once this function returns, the key has been used: the caller's
/// `QuipSigner` knows nothing about broadcasting, so it falls on the
/// caller (typically `QuipWalletClient.buildExecuteUserOp`) to mark the
/// key burned at broadcast time per `SDK_README.md`.
export function signWalletUserOp(params: {
  signer: QuipSigner;
  vaultId: Uint8Array;
  userOp: PackedUserOperation;
  entryPoint: Address;
  chainId: bigint;
  wallet: Address;
  currentKey: CodecAddress;
  nextKey: CodecAddress;
  executeFee: bigint;
}): { signature: Hex; walletDigest: Hex; userOpHash: Hex } {
  const userOpHash = computeUserOpHash(
    params.userOp,
    params.entryPoint,
    params.chainId
  );
  const walletDigest = walletUserOpDigest({
    wallet: params.wallet,
    chainId: params.chainId,
    currentKey: params.currentKey,
    nextKey: params.nextKey,
    userOpHash,
    executeFee: params.executeFee,
  });
  const sigElements = params.signer.sign(
    hexToBytes(walletDigest),
    params.vaultId,
    hexToBytes(params.currentKey.publicSeed)
  );
  const pqSig: WinternitzElements = {
    elements: sigElements.map((el) => toHex(el, { size: 32 })),
  };
  const signature = packWalletSignature(
    params.currentKey,
    params.nextKey,
    pqSig
  );
  return { signature, walletDigest, userOpHash };
}

/// Reverse of `packAccountGasLimits` for inspection. Returns
/// `{ verificationGasLimit, callGasLimit }`.
export function unpackAccountGasLimits(packed: Hex): {
  verificationGasLimit: bigint;
  callGasLimit: bigint;
} {
  const bytes = hexToBytes(packed);
  if (bytes.length !== 32) {
    throw new Error(
      `unpackAccountGasLimits: expected 32 bytes, got ${bytes.length}`
    );
  }
  const verificationGasLimit = BigInt(
    "0x" + toHex(bytes.slice(0, 16)).slice(2)
  );
  const callGasLimit = BigInt("0x" + toHex(bytes.slice(16, 32)).slice(2));
  return { verificationGasLimit, callGasLimit };
}

/// Reverse of `packGasFees` for inspection. Returns
/// `{ maxPriorityFeePerGas, maxFeePerGas }`.
export function unpackGasFees(packed: Hex): {
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
} {
  const bytes = hexToBytes(packed);
  if (bytes.length !== 32) {
    throw new Error(`unpackGasFees: expected 32 bytes, got ${bytes.length}`);
  }
  const maxPriorityFeePerGas = BigInt(
    "0x" + toHex(bytes.slice(0, 16)).slice(2)
  );
  const maxFeePerGas = BigInt("0x" + toHex(bytes.slice(16, 32)).slice(2));
  return { maxPriorityFeePerGas, maxFeePerGas };
}

/// Total `paymasterAndData` length the Quip paymaster expects:
///   52 (header: paymaster + verificationGasLimit + postOpGasLimit)
///   + 6 (validUntil) + 6 (validAfter)
///   + 64 (nextVerifier: publicSeed + publicKeyHash)
///   + 2144 (WOTS+ sig: 67 × 32)
///   = 2272
/// Mirrors `_PAYMASTER_AND_DATA_LEN` in `QuipPaymaster.sol:59`.
export const PAYMASTER_AND_DATA_LEN: number = 2272;

/// Default gas budgets for the paymaster validation + postOp paths.
/// These are conservative — the paymaster operator can override either
/// based on operational data.
export const DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT: bigint = 1_500_000n;
export const DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT: bigint = 100_000n;

/// Construct the `paymasterAndData` field of a sponsored UserOp per the
/// Quip paymaster's layout (`QuipPaymaster.sol:52-59` + `INVARIANTS.md:229`):
///
///   [0:20)     paymaster address
///   [20:36)    validationGasLimit (uint128)
///   [36:52)    postOpGasLimit     (uint128)
///   [52:58)    validUntil         (uint48 / 6 bytes)
///   [58:64)    validAfter         (uint48 / 6 bytes)
///   [64:128)   nextVerifier       (publicSeed + publicKeyHash, 64 bytes)
///   [128:2272) WOTS+ signature    (67 × 32 = 2144 bytes)
///
/// `sig` defaults to all-zeros when omitted (used during digest
/// computation; substitute the real signature once it's produced).
export function packPaymasterAndData(params: {
  paymaster: Address;
  validationGasLimit: bigint;
  postOpGasLimit: bigint;
  validUntil: number; // uint48
  validAfter: number; // uint48
  nextVerifier: CodecAddress;
  sig?: WinternitzElements;
}): Hex {
  if (params.validationGasLimit < 0n || params.validationGasLimit >= 1n << 128n) {
    throw new Error(
      `packPaymasterAndData: validationGasLimit out of uint128 range: ${params.validationGasLimit}`
    );
  }
  if (params.postOpGasLimit < 0n || params.postOpGasLimit >= 1n << 128n) {
    throw new Error(
      `packPaymasterAndData: postOpGasLimit out of uint128 range: ${params.postOpGasLimit}`
    );
  }
  if (params.validUntil < 0 || params.validUntil >= 2 ** 48) {
    throw new Error(
      `packPaymasterAndData: validUntil out of uint48 range: ${params.validUntil}`
    );
  }
  if (params.validAfter < 0 || params.validAfter >= 2 ** 48) {
    throw new Error(
      `packPaymasterAndData: validAfter out of uint48 range: ${params.validAfter}`
    );
  }

  const sigHex =
    params.sig !== undefined
      ? concat(params.sig.elements)
      : (("0x" + "00".repeat(67 * 32)) as Hex);

  const validationGasLimitHex = pad(toHex(params.validationGasLimit), { size: 16 });
  const postOpGasLimitHex = pad(toHex(params.postOpGasLimit), { size: 16 });
  const validUntilHex = pad(toHex(BigInt(params.validUntil)), { size: 6 });
  const validAfterHex = pad(toHex(BigInt(params.validAfter)), { size: 6 });

  return concat([
    params.paymaster,
    validationGasLimitHex,
    postOpGasLimitHex,
    validUntilHex,
    validAfterHex,
    params.nextVerifier.publicSeed,
    params.nextVerifier.publicKeyHash,
    sigHex,
  ]);
}

/// Compute the paymaster digest a WOTS+ verifier signs. Mirrors
/// `QuipPaymaster._verifyAndRotate`. Constituent UserOp fields are used
/// rather than `userOpHash` (which itself contains `paymasterAndData`).
export function paymasterUserOpDigest(params: {
  paymaster: Address;
  chainId: bigint;
  currentVerifier: CodecAddress;
  nextVerifier: CodecAddress;
  sender: Address;
  nonce: bigint;
  callData: Hex;
}): Hex {
  return codecPaymasterUserOpDigest(
    params.paymaster,
    params.chainId,
    params.currentVerifier.publicSeed,
    params.currentVerifier.publicKeyHash,
    params.nextVerifier.publicSeed,
    params.nextVerifier.publicKeyHash,
    params.sender,
    params.nonce,
    params.callData
  );
}

/// Sign a paymaster approval over the provided UserOp. The signing key is
/// the WOTS+ keypair derived from `(vaultId, currentVerifier.publicSeed)`.
/// `signer.sign(...)` auto-burns the key — once this method returns, the
/// `currentVerifier` is dead, exactly per WOTS+ semantics. Caller assembles
/// the final `paymasterAndData` by calling `packPaymasterAndData` with the
/// returned `sig`.
export function signPaymasterUserOp(params: {
  signer: QuipSigner;
  vaultId: Uint8Array;
  paymaster: Address;
  chainId: bigint;
  sender: Address;
  nonce: bigint;
  callData: Hex;
  currentVerifier: CodecAddress;
  nextVerifier: CodecAddress;
}): { sig: WinternitzElements; digest: Hex } {
  const digest = paymasterUserOpDigest({
    paymaster: params.paymaster,
    chainId: params.chainId,
    currentVerifier: params.currentVerifier,
    nextVerifier: params.nextVerifier,
    sender: params.sender,
    nonce: params.nonce,
    callData: params.callData,
  });
  const sigElements = params.signer.sign(
    hexToBytes(digest),
    params.vaultId,
    hexToBytes(params.currentVerifier.publicSeed)
  );
  return {
    sig: {
      elements: sigElements.map((el) => toHex(el, { size: 32 })),
    },
    digest,
  };
}

/// One-shot helper: sign the paymaster approval AND pack the resulting
/// `paymasterAndData` for direct substitution onto the UserOp.
export function buildSignedPaymasterAndData(params: {
  signer: QuipSigner;
  vaultId: Uint8Array;
  paymaster: Address;
  chainId: bigint;
  sender: Address;
  nonce: bigint;
  callData: Hex;
  currentVerifier: CodecAddress;
  nextVerifier: CodecAddress;
  validUntil: number;
  validAfter: number;
  validationGasLimit?: bigint;
  postOpGasLimit?: bigint;
}): { paymasterAndData: Hex; digest: Hex } {
  const { sig, digest } = signPaymasterUserOp({
    signer: params.signer,
    vaultId: params.vaultId,
    paymaster: params.paymaster,
    chainId: params.chainId,
    sender: params.sender,
    nonce: params.nonce,
    callData: params.callData,
    currentVerifier: params.currentVerifier,
    nextVerifier: params.nextVerifier,
  });
  const paymasterAndData = packPaymasterAndData({
    paymaster: params.paymaster,
    validationGasLimit:
      params.validationGasLimit ?? DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
    postOpGasLimit:
      params.postOpGasLimit ?? DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
    validUntil: params.validUntil,
    validAfter: params.validAfter,
    nextVerifier: params.nextVerifier,
    sig,
  });
  return { paymasterAndData, digest };
}

/// Re-export concat for callers that want to assemble paymasterAndData
/// manually before signing.
export { concat };
