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
  type AbiParameter,
  type Address,
  type Hex,
  concat,
  decodeAbiParameters,
  encodeAbiParameters,
  keccak256,
  pad,
  toBytes,
  toHex,
} from "viem";

import { shrincsWalletAbi } from "./abi/ShrincsWallet.js";
import {
  ParameterSetId,
  parameterSetEnumToId,
  parameterSetIdToEnum,
} from "./constants.js";
import {
  type ActionContext,
  type RotationContext,
  type RotationTarget,
  type ShrincsPublicKey,
  type StatefulRotationTarget,
  type StatefulSignature,
  type StatelessSignature,
} from "./types.js";

// Mirrors `ShrincsWalletCodec.sol` + `ShrincsWallet._shrincsDomainSeparator`.
// Every constant/hash here is cross-checked against the committed
// `test/test_vectors/shrincs_*.json` fixtures.

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                      DOMAIN / TAGS                          */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

const keccakUtf8 = (s: string): Hex => keccak256(toBytes(s));

/// Wallet signing-domain tag (combined with chainId + wallet into the
/// `ActionContext.domainSeparator`).
export const DOMAIN_TAG = keccakUtf8("quip-shrincs-wallet-v1");

/// Per-operation `ActionContext.actionType` discriminators.
export const ACTION_ERC4337_EXECUTE = keccakUtf8(
  "quip.shrincs.action.erc4337Execute"
);
export const ACTION_EXECUTE = keccakUtf8("quip.shrincs.action.execute");
export const ACTION_WITHDRAW = keccakUtf8("quip.shrincs.action.withdrawDeposit");
export const ACTION_UPGRADE = keccakUtf8("quip.shrincs.action.upgrade");
export const ACTION_TRANSFER_OWNERSHIP = keccakUtf8(
  "quip.shrincs.action.transferOwnership"
);
export const ACTION_SET_ERC1271_KEY = keccakUtf8(
  "quip.shrincs.action.setErc1271Key"
);
export const ACTION_ROTATE_KEY = keccakUtf8("quip.shrincs.action.rotateKey");
export const ACTION_ERC1271 = keccakUtf8("quip.shrincs.action.erc1271");

const ZERO32 = ("0x" + "00".repeat(32)) as Hex;

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    WORD / HASH HELPERS                      */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// Left-pad a value to a 32-byte word (mirrors Solidity `bytes32(uint256(x))`).
const word = (value: bigint | number): Hex => toHex(BigInt(value), { size: 32 });

/// Address as a 32-byte word (mirrors `bytes32(uint256(uint160(addr)))`).
const addressWord = (addr: Address): Hex => pad(addr, { size: 32 });

/// keccak256 of the concatenation of 32-byte words — the TS image of solady
/// `EfficientHashLib.hash(...)`.
const hashWords = (...words: Hex[]): Hex => keccak256(concat(words));

/// keccak256 over arbitrary calldata (`dataHash` / `migratorHash`).
export const dataHash = (data: Hex): Hex => keccak256(data);

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                  DOMAIN SEPARATOR / COMMITMENT             */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// `ActionContext.domainSeparator` for a wallet/paymaster:
/// `keccak256(DOMAIN_TAG ‖ pad32(chainId) ‖ pad32(address))`. Pass the
/// paymaster tag via `domainTag` for the sponsorship domain.
export function domainSeparator(
  chainId: bigint | number,
  contractAddress: Address,
  domainTag: Hex = DOMAIN_TAG
): Hex {
  return hashWords(domainTag, word(chainId), addressWord(contractAddress));
}

/// Bundle commitment as the contract/keygen computes it:
/// `keccak256("shrincs-public-key" ‖ packedParamSet ‖ statefulPublicKey ‖ pkSeed ‖ hypertreeRoot)`.
/// Used to derive the `publicKeyCommitment` of a rotation target whose stateless
/// half is reused (e.g. `rotateKey`).
export function publicKeyCommitment(parts: {
  parameterSetId: ParameterSetId;
  statefulPublicKey: Hex;
  pkSeed: Hex;
  hypertreeRoot: Hex;
}): Hex {
  return keccak256(
    concat([
      toHex(toBytes("shrincs-public-key")),
      toHex(parts.parameterSetId, { size: 1 }),
      parts.statefulPublicKey,
      parts.pkSeed,
      parts.hypertreeRoot,
    ])
  );
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                     PAYLOAD HASHES                          */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

export const erc4337PayloadHash = (userOpHash: Hex, fee: bigint): Hex =>
  hashWords(userOpHash, word(fee));

export const executePayloadHash = (
  target: Address,
  value: bigint,
  dataKeccak: Hex,
  fee: bigint
): Hex => hashWords(addressWord(target), word(value), dataKeccak, word(fee));

export const withdrawPayloadHash = (to: Address, amount: bigint): Hex =>
  hashWords(addressWord(to), word(amount));

export const upgradePayloadHash = (
  newImplementation: Address,
  shouldMigrate: boolean,
  migratorHash: Hex
): Hex =>
  hashWords(
    addressWord(newImplementation),
    word(shouldMigrate ? 1 : 0),
    migratorHash
  );

export const transferOwnershipPayloadHash = (
  newOwner: Address,
  nextCommitment: Hex
): Hex => hashWords(addressWord(newOwner), nextCommitment);

export const setErc1271KeyPayloadHash = (
  newCommitment: Hex,
  newParameterSetId: ParameterSetId
): Hex => hashWords(newCommitment, word(newParameterSetId));

export const rotateKeyPayloadHash = (
  nextCommitment: Hex,
  nextParameterSetId: ParameterSetId
): Hex => hashWords(nextCommitment, word(nextParameterSetId));

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    CONTEXT BUILDERS                         */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// Assemble a stateful `ActionContext`. On the stateful path `nonce` is always
/// `0` (anti-replay is the on-chain used-leaf bitmap).
export function buildActionContext(params: {
  domainSeparator: Hex;
  keyVersion: bigint;
  actionType: Hex;
  payloadHash: Hex;
  nonce?: bigint;
}): ActionContext {
  return {
    domainSeparator: params.domainSeparator,
    nonce: params.nonce === undefined ? ZERO32 : word(params.nonce),
    keyVersion: word(params.keyVersion),
    actionType: params.actionType,
    payloadHash: params.payloadHash,
  };
}

export function buildRotationContext(params: {
  domainSeparator: Hex;
  nonce: bigint;
  keyVersion: bigint;
}): RotationContext {
  return {
    domainSeparator: params.domainSeparator,
    nonce: word(params.nonce),
    keyVersion: word(params.keyVersion),
  };
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                   ABI STRUCT PARAMETERS                     */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

// The SHRINCS struct tuple shapes are extracted directly from the generated
// `shrincsWalletAbi` (keyed by Solidity `internalType`) rather than re-declared
// here, so the codec stays a single source of truth with the contract: a struct
// change regenerates the ABI and these follow automatically. The nested
// `StatelessSignature` (Fors/Hypertree/WotsC) is pulled in whole by one lookup.
function findStructTuple(internalType: string): AbiParameter {
  const search = (params: readonly AbiParameter[]): AbiParameter | undefined => {
    for (const p of params) {
      if (p.internalType === internalType) return p;
      if ("components" in p && p.components) {
        const hit = search(p.components);
        if (hit) return hit;
      }
    }
    return undefined;
  };
  for (const item of shrincsWalletAbi as readonly { type: string; inputs?: readonly AbiParameter[] }[]) {
    if (item.type === "function" && item.inputs) {
      const hit = search(item.inputs);
      // structuredClone detaches from the readonly `as const` ABI; we drop the
      // function's param name since the codec only uses these positionally.
      if (hit) return { ...(structuredClone(hit) as AbiParameter), name: undefined };
    }
  }
  throw new Error(`struct ${internalType} not found in shrincsWalletAbi`);
}

const PUBLIC_KEY_TUPLE = findStructTuple("struct ShrincsTypes.PublicKey");
const STATEFUL_SIGNATURE_TUPLE = findStructTuple("struct ShrincsTypes.StatefulSignature");
const STATELESS_SIGNATURE_TUPLE = findStructTuple("struct ShrincsTypes.StatelessSignature");

/// On-chain `PublicKey` carries the parameter set as a uint8 enum, while the
/// SDK/WASM shape uses the string id. These converters bridge the two. The
/// `publicKeyToAbi` form is what the wallet client passes as the direct struct
/// argument to the owner-path functions (`execute`, `rotateKey`, …).
export function publicKeyToAbi(pk: ShrincsPublicKey) {
  return {
    parameterSetId: parameterSetIdToEnum(pk.parameterSetId),
    statefulPublicKey: pk.statefulPublicKey,
    publicKeyCommitment: pk.publicKeyCommitment,
    pkSeed: pk.pkSeed,
    hypertreeRoot: pk.hypertreeRoot,
  };
}

function publicKeyFromAbi(t: {
  parameterSetId: number;
  statefulPublicKey: Hex;
  publicKeyCommitment: Hex;
  pkSeed: Hex;
  hypertreeRoot: Hex;
}): ShrincsPublicKey {
  return {
    parameterSetId: parameterSetEnumToId(t.parameterSetId),
    statefulPublicKey: t.statefulPublicKey,
    publicKeyCommitment: t.publicKeyCommitment,
    pkSeed: t.pkSeed,
    hypertreeRoot: t.hypertreeRoot,
  };
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    BLOB ENCODE / DECODE                     */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// Factory init payload: `[0:32]commitment ‖ [32:64]pkSeed ‖ abi(PublicKey,
/// uint8 parameterSetId, bytes32 erc1271Commitment, uint8 erc1271ParameterSetId)`.
export function encodeInitPayload(params: {
  mainBundle: ShrincsPublicKey;
  erc1271Commitment: Hex;
  erc1271ParameterSetId: ParameterSetId;
}): Hex {
  const commitment = params.mainBundle.publicKeyCommitment;
  const pkSeed = params.mainBundle.pkSeed;
  return encodeAbiParameters(
    [
      { name: "commitment", type: "bytes32" },
      { name: "pkSeed", type: "bytes32" },
      PUBLIC_KEY_TUPLE,
      { name: "parameterSetId", type: "uint8" },
      { name: "erc1271Commitment", type: "bytes32" },
      { name: "erc1271ParameterSetId", type: "uint8" },
    ],
    [
      commitment,
      pkSeed,
      publicKeyToAbi(params.mainBundle),
      parameterSetIdToEnum(params.mainBundle.parameterSetId),
      params.erc1271Commitment,
      params.erc1271ParameterSetId,
    ]
  );
}

/// ERC-4337 `userOp.signature` = `abi.encode(PublicKey, StatefulSignature)`.
export function encodeUserOpSignature(
  publicKey: ShrincsPublicKey,
  signature: StatefulSignature
): Hex {
  return encodeAbiParameters(
    [PUBLIC_KEY_TUPLE, STATEFUL_SIGNATURE_TUPLE],
    [publicKeyToAbi(publicKey), signature]
  );
}

export function decodeUserOpSignature(blob: Hex): {
  publicKey: ShrincsPublicKey;
  signature: StatefulSignature;
} {
  const [pk, signature] = decodeAbiParameters(
    [PUBLIC_KEY_TUPLE, STATEFUL_SIGNATURE_TUPLE],
    blob
  ) as unknown as [Parameters<typeof publicKeyFromAbi>[0], StatefulSignature];
  return { publicKey: publicKeyFromAbi(pk), signature };
}

/// UUPS `upgradeToAndCall` data = `abi.encode(PublicKey, StatefulSignature,
/// bool shouldMigrate, bytes migratorPayload)`.
export function encodeUpgradeData(params: {
  publicKey: ShrincsPublicKey;
  signature: StatefulSignature;
  shouldMigrate: boolean;
  migratorPayload: Hex;
}): Hex {
  return encodeAbiParameters(
    [
      PUBLIC_KEY_TUPLE,
      STATEFUL_SIGNATURE_TUPLE,
      { name: "shouldMigrate", type: "bool" },
      { name: "migratorPayload", type: "bytes" },
    ],
    [
      publicKeyToAbi(params.publicKey),
      params.signature,
      params.shouldMigrate,
      params.migratorPayload,
    ]
  );
}

/// ERC-1271 signature blob = `abi.encode(PublicKey, StatelessSignature, bytes ecdsaSig)`.
export function encodeErc1271Signature(params: {
  publicKey: ShrincsPublicKey;
  signature: StatelessSignature;
  ecdsaSig: Hex;
}): Hex {
  return encodeAbiParameters(
    [
      PUBLIC_KEY_TUPLE,
      STATELESS_SIGNATURE_TUPLE,
      { name: "ecdsaSig", type: "bytes" },
    ],
    [publicKeyToAbi(params.publicKey), params.signature, params.ecdsaSig]
  );
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*               ROTATION-TARGET HELPERS / ABI                */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// Build the `StatefulRotationTarget` for `rotateKey` from a fresh stateful
/// public key, reusing the current bundle's stateless half. `publicKeyCommitment`
/// is derived to match the on-chain commitment formula.
export function buildStatefulRotationTarget(params: {
  parameterSetId: string;
  nextStatefulPublicKey: Hex;
  currentPkSeed: Hex;
  currentHypertreeRoot: Hex;
}): StatefulRotationTarget {
  const enumId = parameterSetIdToEnum(params.parameterSetId);
  return {
    parameterSetId: params.parameterSetId,
    statefulPublicKey: params.nextStatefulPublicKey,
    publicKeyCommitment: publicKeyCommitment({
      parameterSetId: enumId,
      statefulPublicKey: params.nextStatefulPublicKey,
      pkSeed: params.currentPkSeed,
      hypertreeRoot: params.currentHypertreeRoot,
    }),
  };
}

/// Full rotation target = the incoming bundle's public key (recoverWallet /
/// transferOwnership).
export function toRotationTarget(pk: ShrincsPublicKey): RotationTarget {
  return {
    parameterSetId: pk.parameterSetId,
    statefulPublicKey: pk.statefulPublicKey,
    publicKeyCommitment: pk.publicKeyCommitment,
    pkSeed: pk.pkSeed,
    hypertreeRoot: pk.hypertreeRoot,
  };
}

// Exposed for the wallet client's calldata encoding of the struct args. (The
// owner-path functions take SHRINCS structs as direct args, encoded via the
// contract ABI; these tuple shapes are also useful for tests.)
export const abiTuples = {
  publicKey: PUBLIC_KEY_TUPLE,
  statefulSignature: STATEFUL_SIGNATURE_TUPLE,
  statelessSignature: STATELESS_SIGNATURE_TUPLE,
} satisfies Record<string, AbiParameter>;
