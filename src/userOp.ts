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
import { type Address, type Hex } from "viem";

import {
  DEFAULT_CALL_GAS_LIMIT,
  DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
  DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
  DEFAULT_PRE_VERIFICATION_GAS,
  DEFAULT_VERIFICATION_GAS_LIMIT,
} from "./constants.js";
import { QuipSigner } from "./signer.js";
import {
  type PackedUserOperation,
  type WinternitzAddress,
  type WinternitzElements,
  computeUserOpHash,
  encodeUserOpSignature,
  erc4337ExecuteDigest,
  packAccountGasLimits,
  packGasFees,
  packPaymasterAndData,
  paymasterUserOpDigest,
} from "./wotsCodec.js";

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
/// `codec.erc4337ExecuteDigest` and assembling via `codec.encodeUserOpSignature`,
/// then substituting `signature` on the returned struct (or use
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

/// Sign a UserOp with a WOTS+ key. Computes the EntryPoint userOpHash,
/// wraps it in the wallet-side digest (`codec.erc4337ExecuteDigest`),
/// signs via `QuipSigner`, and returns the assembled signature bytes.
/// Caller substitutes this into `userOp.signature` before submitting to
/// the EntryPoint.
///
/// The signing key is the WOTS+ keypair derived from `(vaultId, currentKey.publicSeed)`.
/// `QuipSigner.sign(...)` auto-burns the key — once this function returns,
/// the `currentKey` is dead in the signer.
export function signWalletUserOp(params: {
  signer: QuipSigner;
  vaultId: Hex;
  userOp: PackedUserOperation;
  entryPoint: Address;
  chainId: bigint;
  wallet: Address;
  currentKey: WinternitzAddress;
  nextKey: WinternitzAddress;
  executeFee: bigint;
}): { signature: Hex; walletDigest: Hex; userOpHash: Hex } {
  const userOpHash = computeUserOpHash(
    params.userOp,
    params.entryPoint,
    params.chainId
  );
  const walletDigest = erc4337ExecuteDigest(
    params.wallet,
    params.chainId,
    params.currentKey.publicSeed,
    params.currentKey.publicKeyHash,
    params.nextKey.publicSeed,
    params.nextKey.publicKeyHash,
    userOpHash,
    params.executeFee
  );
  const pqSig: WinternitzElements = {
    elements: params.signer.sign(
      walletDigest,
      params.vaultId,
      params.currentKey.publicSeed
    ),
  };
  const signature = encodeUserOpSignature(
    params.currentKey,
    params.nextKey,
    pqSig
  );
  return { signature, walletDigest, userOpHash };
}

/// Sign a paymaster approval over the provided UserOp. The signing key is
/// the WOTS+ keypair derived from `(vaultId, currentVerifier.publicSeed)`.
/// `signer.sign(...)` auto-burns the key — once this method returns, the
/// `currentVerifier` is dead, exactly per WOTS+ semantics. Caller assembles
/// the final `paymasterAndData` by calling `codec.packPaymasterAndData` with
/// the returned `sig`.
export function signPaymasterUserOp(params: {
  signer: QuipSigner;
  vaultId: Hex;
  paymaster: Address;
  chainId: bigint;
  sender: Address;
  nonce: bigint;
  callData: Hex;
  currentVerifier: WinternitzAddress;
  nextVerifier: WinternitzAddress;
}): { sig: WinternitzElements; digest: Hex } {
  const digest = paymasterUserOpDigest(
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
  return {
    sig: {
      elements: params.signer.sign(
        digest,
        params.vaultId,
        params.currentVerifier.publicSeed
      ),
    },
    digest,
  };
}

/// One-shot helper: sign the paymaster approval AND pack the resulting
/// `paymasterAndData` for direct substitution onto the UserOp.
export function buildSignedPaymasterAndData(params: {
  signer: QuipSigner;
  vaultId: Hex;
  paymaster: Address;
  chainId: bigint;
  sender: Address;
  nonce: bigint;
  callData: Hex;
  currentVerifier: WinternitzAddress;
  nextVerifier: WinternitzAddress;
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
