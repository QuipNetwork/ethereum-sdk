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

/// Re-export concat for callers that want to assemble paymasterAndData
/// manually before signing. Phase 5b adds typed helpers for the Quip
/// paymaster layout.
export { concat };
