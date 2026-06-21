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
import { type Address, type Hex, concat, keccak256, toBytes, toHex } from "viem";

// The ERC-4337 v0.7 userOp plumbing (packed type, gas-limit packing, the
// canonical userOpHash) is signature-scheme-agnostic, so the Shrincs SDK reuses
// the v1 implementations rather than duplicating them.
import {
  type PackedUserOperation,
  computeUserOpHash,
  packAccountGasLimits,
  packGasFees,
} from "../wotsCodec.js";
import {
  ACTION_ERC4337_EXECUTE,
  buildActionContext,
  domainSeparator,
  encodeUserOpSignature,
  erc4337PayloadHash,
} from "./shrincsCodec.js";
import {
  DEFAULT_CALL_GAS_LIMIT,
  DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
  DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
  DEFAULT_PRE_VERIFICATION_GAS,
  DEFAULT_VERIFICATION_GAS_LIMIT,
} from "./constants.js";
import { type ShrincsKeyPair } from "./shrincsSigner.js";
import { type ShrincsPublicKey, type StatefulSignature } from "./types.js";

export { type PackedUserOperation } from "../wotsCodec.js";

/// Paymaster sponsorship domain/action (mirror `ShrincsPaymaster.sol`).
export const PAYMASTER_DOMAIN_TAG = keccak256(toBytes("quip-shrincs-paymaster-v1"));
export const ACTION_PAYMASTER_APPROVE = keccak256(
  toBytes("quip.shrincs.action.paymasterApprove")
);

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
  executeFee: bigint;
  keyVersion: bigint;
  /// Lowest unused stateful leaf, read from the on-chain bitmap by the client.
  leaf: number;
}

export interface SignedWalletUserOp {
  /// Ready to substitute into `userOp.signature`.
  signature: Hex;
  userOpHash: Hex;
}

/// Sign a wallet ERC-4337 userOp: bind the EntryPoint `userOpHash` + execute fee
/// into the canonical `ACTION_ERC4337_EXECUTE` action, sign at `leaf`, and ABI
/// pack `(PublicKey, StatefulSignature)` into the signature field.
export function signWalletUserOp(
  params: SignWalletUserOpParams
): SignedWalletUserOp {
  const userOpHash = computeUserOpHash(params.userOp, params.entryPoint, params.chainId);
  const ctx = buildActionContext({
    domainSeparator: domainSeparator(params.chainId, params.wallet),
    keyVersion: params.keyVersion,
    actionType: ACTION_ERC4337_EXECUTE,
    payloadHash: erc4337PayloadHash(userOpHash, params.executeFee),
  });
  const signature = params.keypair.signStatefulActionAt(ctx, params.leaf);
  return {
    signature: encodeUserOpSignature(params.keypair.publicKey, signature),
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
  return concat([params.header64, encodeUserOpSignature(params.publicKey, params.signature)]);
}

export interface SignPaymasterUserOpParams {
  keypair: ShrincsKeyPair;
  userOp: PackedUserOperation;
  paymaster: Address;
  chainId: bigint;
  keyVersion: bigint;
  verificationGasLimit?: bigint;
  postOpGasLimit?: bigint;
  validUntil?: number;
  validAfter?: number;
  /// Lowest unused stateful leaf on the paymaster, read from chain by the client.
  leaf: number;
}

/// Produce the fully-signed `paymasterAndData` for a sponsored userOp. Binds the
/// sponsorship to the specific wallet via the userOp's `sender`, so one global
/// verifier key safely covers all wallets.
export function signPaymasterUserOp(params: SignPaymasterUserOpParams): Hex {
  const header64 = packPaymasterHeader({
    paymaster: params.paymaster,
    verificationGasLimit:
      params.verificationGasLimit ?? DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
    postOpGasLimit: params.postOpGasLimit ?? DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
    validUntil: params.validUntil ?? 0,
    validAfter: params.validAfter ?? 0,
  });
  // The binding covers the header (which is `paymasterAndData[0:64)` at verify
  // time), so feed the header in as the truncated paymasterAndData.
  const bindingHash = paymasterBindingHash(params.userOp, header64);
  const ctx = buildActionContext({
    domainSeparator: domainSeparator(params.chainId, params.paymaster, PAYMASTER_DOMAIN_TAG),
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
