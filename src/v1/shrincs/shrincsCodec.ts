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
  hexToBytes,
  keccak256,
  pad,
  size,
  sliceHex,
  toBytes,
  toHex,
} from "viem";

import { shrincsWalletAbi } from "./abi/ShrincsWallet.js";
import { shrincsWalletBeta2Abi } from "./versions/v1_0_1_beta2/abi.js";
import {
  ERC1271_ECDSA_BYTES,
  ERC1271_MAGIC,
  ERC1271_SIGNATURE_BYTES,
  ERC1271_VERSION,
  HASH_SUITE_KECCAK_256,
  SHRINCS_PROFILE_ID,
  STATELESS_PK_BYTES,
  STATELESS_PQ_BYTES,
} from "./constants.js";
import {
  MalformedCodecPayloadError,
  StatelessEncodingLengthError,
} from "./errors.js";
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

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                      DOMAIN / TAGS                          */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

const keccakUtf8 = (s: string): Hex => keccak256(toBytes(s));

/// Wallet signing-domain tag (combined with chainId + wallet into the
/// `ActionContext.domainSeparator`).
export const DOMAIN_TAG = keccakUtf8("quip-shrincs-wallet-v1");

/// Paymaster signing-domain tag (combined with chainId + paymaster into the
/// sponsorship `ActionContext.domainSeparator`).
export const PAYMASTER_DOMAIN_TAG = keccakUtf8("quip-shrincs-paymaster-v1");

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
export const ACTION_MARK_LEAVES_USED = keccakUtf8(
  "quip.shrincs.action.markLeavesUsed"
);
export const ACTION_ERC1271 = keccakUtf8("quip.shrincs.action.erc1271");
export const ACTION_PAYMASTER_APPROVE = keccakUtf8(
  "quip.shrincs.action.paymasterApprove"
);

/// Per-path tags folded into `RotationContext.domainSeparator` (see
/// `rotationDomainSeparator`). `RotationContext` carries no action
/// discriminator, so distinct tags are what keep a `transferOwnership`
/// recovery signature from doubling as a `recoverWallet` input.
export const ROTATION_DOMAIN_RECOVER_WALLET = keccakUtf8(
  "quip.shrincs.rotation.recoverWallet"
);
export const ROTATION_DOMAIN_TRANSFER_OWNERSHIP = keccakUtf8(
  "quip.shrincs.rotation.transferOwnership"
);

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

/// `RotationContext.domainSeparator` for one stateless-rotation path:
/// the wallet's base signing domain with a per-path `ROTATION_DOMAIN_*` tag
/// folded in (mirrors `ShrincsWalletCodec.rotationDomainSeparator`).
export function rotationDomainSeparator(base: Hex, tag: Hex): Hex {
  return hashWords(base, tag);
}

/// The compile-time SHRINCS profile this SDK is built against — must equal
/// `SHRINCSParams.PROFILE_NAME` of the on-chain verifier (the `shrincs-profile/`
/// remapping selects `profiles/256s` + keccak).
export const SHRINCS_PROFILE_NAME = "shrincs-256s-keccak";

/// Bundle commitment as the contract/keygen computes it, profile-bound:
/// `keccak256("shrincs-public-key/" ‖ PROFILE_NAME ‖ statefulPublicKey ‖ pkSeed
/// ‖ hypertreeRoot)` (raw ASCII, no length prefixes). Used to derive the
/// `publicKeyCommitment` of a rotation target whose stateless half is reused
/// (e.g. `rotateKey`).
export function publicKeyCommitment(parts: {
  statefulPublicKey: Hex;
  pkSeed: Hex;
  hypertreeRoot: Hex;
}): Hex {
  return keccak256(
    concat([
      toHex(toBytes("shrincs-public-key/")),
      toHex(toBytes(SHRINCS_PROFILE_NAME)),
      parts.statefulPublicKey,
      parts.pkSeed,
      parts.hypertreeRoot,
    ])
  );
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                 CANONICAL MESSAGE HASHES                    */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

// Mirrors `SHRINCS.sol`'s canonical message-hash constructions verbatim
// (V4 verifier). Through hashsigs-wasm 0.2.0-rc.2 these lived behind wasm
// entry points (`shrincsStatefulActionMessageHash` et al.); the current
// wasm dropped them, and they are plain
// `keccak256(abi.encodePacked(...))`, so the SDK computes them here. The
// cross-language agreement is pinned by the digest vectors in
// tests/shrincsCodec.test.ts.

/// Operation tags domain-separating each signed message family
/// (`SHRINCS.OP_*`).
export const OP_VERIFY_STATEFUL = keccakUtf8("shrincs-verify-stateful");
export const OP_VERIFY_STATELESS = keccakUtf8("shrincs-verify-stateless");
export const OP_ROTATE_FULL = keccakUtf8("shrincs-rotate-full");

/// `HashSuite.HASH_SUITE_ID` as `abi.encodePacked(uint32)` — 4 bytes BE.
const HASH_SUITE_ID_BE4: Hex = toHex(HASH_SUITE_KECCAK_256, { size: 4 });

/// `SHRINCS.statefulActionMessageHash`: op tag ‖ suite id ‖ installed-key
/// commitment ‖ the five ActionContext words.
export function statefulActionMessageHash(
  expectedPublicKeyCommitment: Hex,
  context: ActionContext
): Hex {
  return keccak256(
    concat([
      OP_VERIFY_STATEFUL,
      HASH_SUITE_ID_BE4,
      expectedPublicKeyCommitment,
      context.domainSeparator,
      context.nonce,
      context.keyVersion,
      context.actionType,
      context.payloadHash,
    ])
  );
}

/// `SHRINCS.statelessActionMessageHash`: the stateless-path twin of
/// `statefulActionMessageHash` under its own operation tag.
export function statelessActionMessageHash(
  expectedPublicKeyCommitment: Hex,
  context: ActionContext
): Hex {
  return keccak256(
    concat([
      OP_VERIFY_STATELESS,
      HASH_SUITE_ID_BE4,
      expectedPublicKeyCommitment,
      context.domainSeparator,
      context.nonce,
      context.keyVersion,
      context.actionType,
      context.payloadHash,
    ])
  );
}

// The wallet delegates ALL signature verification to the deployed
// `SHRINCSVerifier` (see ShrincsWallet.sol, EXTERNAL VERIFIER DELEGATION),
// whose V4 ERC-7913 adapters bind `*RawMessageHash(commitment, hash)` over
// the caller-supplied hash. Signed digests are therefore the canonical
// action/rotation hash wrapped once more in the matching raw binding.

/// `SHRINCS.statefulRawMessageHash` — the V4 binding
/// `SHRINCSVerifier.verify` (stateful) applies to its caller hash.
export function statefulRawMessageHash(
  expectedPublicKeyCommitment: Hex,
  hash: Hex
): Hex {
  return keccak256(
    concat([
      OP_VERIFY_STATEFUL,
      HASH_SUITE_ID_BE4,
      expectedPublicKeyCommitment,
      hash,
    ])
  );
}

/// `SHRINCS.statelessRawMessageHash` — the V4 binding
/// `SHRINCSVerifier.verifyStateless` applies to its caller hash.
export function statelessRawMessageHash(
  expectedPublicKeyCommitment: Hex,
  hash: Hex
): Hex {
  return keccak256(
    concat([
      OP_VERIFY_STATELESS,
      HASH_SUITE_ID_BE4,
      expectedPublicKeyCommitment,
      hash,
    ])
  );
}

/// `SHRINCS.fullRotationMessageHash`: op tag ‖ suite id ‖ installed-key
/// commitment ‖ rotation context ‖ current and next bundle commitments.
export function fullRotationMessageHash(
  expectedPublicKeyCommitment: Hex,
  currentPublicKey: ShrincsPublicKey,
  context: RotationContext,
  nextKey: RotationTarget
): Hex {
  return keccak256(
    concat([
      OP_ROTATE_FULL,
      HASH_SUITE_ID_BE4,
      expectedPublicKeyCommitment,
      context.domainSeparator,
      context.nonce,
      context.keyVersion,
      currentPublicKey.publicKeyCommitment,
      nextKey.publicKeyCommitment,
    ])
  );
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                     PAYLOAD HASHES                          */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// ONE word — no fee: the signer's `maxFee` ceiling rides in `callData`, which
/// `userOpHash` already commits to (ERC-7562: validation must not read the
/// factory's live fee).
export const erc4337PayloadHash = (userOpHash: Hex): Hex =>
  hashWords(userOpHash);

/// `maxFee` is the signer's fee CEILING, not the charged amount: execution
/// reads the factory's live fee and reverts `ExecuteFeeExceedsCap` only if it
/// exceeds this cap (decreases succeed at the lower price).
export const executePayloadHash = (
  target: Address,
  value: bigint,
  dataKeccak: Hex,
  maxFee: bigint
): Hex => hashWords(addressWord(target), word(value), dataKeccak, word(maxFee));

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
  newHashSuite: number = HASH_SUITE_KECCAK_256
): Hex => hashWords(newCommitment, word(newHashSuite));

export const rotateKeyPayloadHash = (nextCommitment: Hex): Hex =>
  hashWords(nextCommitment);

/// Commitment to a `markLeavesUsed` target array: one 32-byte word per leaf
/// index, in order (the TS image of the wallet's EfficientHashLib word buffer).
/// Order-sensitive by construction — the signed payload authorizes exactly this
/// array, so a submitter can neither add, drop, nor reorder targets.
export const leavesHash = (leaves: readonly number[]): Hex =>
  hashWords(...leaves.map((leaf) => word(leaf)));

/// `payloadHash` for `markLeavesUsed` (surgical batch leaf revocation): binds
/// the `leavesHash` commitment over the exact target array.
export const markLeavesUsedPayloadHash = (leavesHashValue: Hex): Hex =>
  hashWords(leavesHashValue);

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    CONTEXT BUILDERS                         */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// Assemble a stateful `ActionContext`. `nonce` is REQUIRED and must be the
/// wallet's live `actionNonce()` at verification time: the wallet binds it into
/// every signed context and advances it on every consumed signature, so a
/// signature dies the moment any later signature lands (supersession). The
/// paymaster path is the one deliberate exception — it binds `0n` (its
/// freshness is the validUntil/validAfter window).
export function buildActionContext(params: {
  domainSeparator: Hex;
  nonce: bigint;
  keyVersion: bigint;
  actionType: Hex;
  payloadHash: Hex;
}): ActionContext {
  return {
    domainSeparator: params.domainSeparator,
    nonce: word(params.nonce),
    keyVersion: word(params.keyVersion),
    actionType: params.actionType,
    payloadHash: params.payloadHash,
  };
}

/// The `ActionContext` the INCOMING bundle signs to accept a `transferOwnership`
/// handover (mirrors `ShrincsWallet._verifyOwnershipAcceptance`): the wallet's
/// domain, `ACTION_TRANSFER_OWNERSHIP`, the handover payload — and nonce 0 /
/// keyVersion 0 rather than live values. The acceptance is bound to the
/// incoming commitment (which the wallet can install at most once) and to
/// `newOwner`, so it authorizes exactly one install and cannot go stale while
/// the current owner keeps transacting. Signed against the INCOMING commitment,
/// never the installed one.
export function buildOwnershipAcceptanceContext(params: {
  domainSeparator: Hex;
  newOwner: Address;
  nextCommitment: Hex;
}): ActionContext {
  return buildActionContext({
    domainSeparator: params.domainSeparator,
    nonce: 0n,
    keyVersion: 0n,
    actionType: ACTION_TRANSFER_OWNERSHIP,
    payloadHash: transferOwnershipPayloadHash(
      params.newOwner,
      params.nextCommitment
    ),
  });
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
// change regenerates the ABI and these follow automatically.
type AbiFunctions = readonly { type: string; inputs?: readonly AbiParameter[] }[];

function findStructTuple(
  internalType: string,
  abi: AbiFunctions = shrincsWalletAbi as AbiFunctions
): AbiParameter {
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
  for (const item of abi) {
    if (item.type === "function" && item.inputs) {
      const hit = search(item.inputs);
      // structuredClone detaches from the readonly `as const` ABI; we drop the
      // function's param name since the codec only uses these positionally.
      if (hit) return { ...(structuredClone(hit) as AbiParameter), name: undefined };
    }
  }
  throw new Error(`struct ${internalType} not found in the wallet ABI`);
}

const PUBLIC_KEY_TUPLE = findStructTuple("struct SHRINCS.PublicKey");
const STATEFUL_SIGNATURE_TUPLE = findStructTuple("struct SHRINCS.Signature");
// The stateless signature is no longer an ABI struct on chain (hashsigs 0.4.0
// uses the fixed layout below). The struct form survives in two places: the
// wasm signer's output, and the frozen V1.0.1-beta.2 generation's calldata. Its
// tuple shape is therefore read from that generation's ABI snapshot.
const STATELESS_SIGNATURE_TUPLE = findStructTuple(
  "struct SPHINCSPlusC.Signature",
  shrincsWalletBeta2Abi as AbiFunctions
);

/// The on-chain `PublicKey` struct now matches the SDK/WASM shape field-for-field
/// (no parameter-set discriminator). These converters survive as explicit
/// projections so decoded tuples come back as plain `ShrincsPublicKey` objects.
export function publicKeyToAbi(pk: ShrincsPublicKey) {
  return {
    statefulPublicKey: pk.statefulPublicKey,
    publicKeyCommitment: pk.publicKeyCommitment,
    pkSeed: pk.pkSeed,
    hypertreeRoot: pk.hypertreeRoot,
  };
}

function publicKeyFromAbi(t: {
  statefulPublicKey: Hex;
  publicKeyCommitment: Hex;
  pkSeed: Hex;
  hypertreeRoot: Hex;
}): ShrincsPublicKey {
  return {
    statefulPublicKey: t.statefulPublicKey,
    publicKeyCommitment: t.publicKeyCommitment,
    pkSeed: t.pkSeed,
    hypertreeRoot: t.hypertreeRoot,
  };
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                    BLOB ENCODE / DECODE                     */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// Factory init / migrate payload ABI: `abi.encode(bytes32 commitment,
/// bytes32 pkSeed, PublicKey mainBundle, uint32 hashSuite, PublicKey
/// erc1271Bundle, uint32 erc1271HashSuite)`. Head words land at `[0:32)
/// commitment, [32:64) pkSeed` by ABI order.
const INIT_PAYLOAD_PARAMS: AbiParameter[] = [
  { name: "commitment", type: "bytes32" },
  { name: "pkSeed", type: "bytes32" },
  PUBLIC_KEY_TUPLE,
  { name: "hashSuite", type: "uint32" },
  PUBLIC_KEY_TUPLE,
  { name: "erc1271HashSuite", type: "uint32" },
];

/// Factory init payload: `abi.encode(bytes32 commitment, bytes32 pkSeed,
/// PublicKey mainBundle, uint32 hashSuite, PublicKey erc1271Bundle, uint32
/// erc1271HashSuite)`. Both suites default to keccak-256 — the only suite the
/// wallet accepts. The ERC-1271 key travels as a FULL bundle: the wallet
/// derives its commitment on-chain and spends all four trees (main + 1271,
/// stateful + stateless) in the lifetime registries.
export function encodeInitPayload(params: {
  mainBundle: ShrincsPublicKey;
  erc1271Bundle: ShrincsPublicKey;
  hashSuite?: number;
  erc1271HashSuite?: number;
}): Hex {
  const commitment = params.mainBundle.publicKeyCommitment;
  const pkSeed = params.mainBundle.pkSeed;
  return encodeAbiParameters(INIT_PAYLOAD_PARAMS, [
    commitment,
    pkSeed,
    publicKeyToAbi(params.mainBundle),
    params.hashSuite ?? HASH_SUITE_KECCAK_256,
    publicKeyToAbi(params.erc1271Bundle),
    params.erc1271HashSuite ?? HASH_SUITE_KECCAK_256,
  ]);
}

/// Invert `encodeInitPayload`: recover both bundles from an install / migrate
/// payload. Malformed blobs throw `MalformedCodecPayloadError` (same 0xc0-byte
/// floor as on-chain `decodeInit`).
export function decodeInitPayload(payload: Hex): {
  mainBundle: ShrincsPublicKey;
  erc1271Bundle: ShrincsPublicKey;
} {
  try {
    const decoded = decodeAbiParameters(INIT_PAYLOAD_PARAMS, payload);
    type AbiPublicKey = Parameters<typeof publicKeyFromAbi>[0];
    return {
      mainBundle: publicKeyFromAbi(decoded[2] as AbiPublicKey),
      erc1271Bundle: publicKeyFromAbi(decoded[4] as AbiPublicKey),
    };
  } catch {
    throw new MalformedCodecPayloadError(0xc0n, BigInt(size(payload)));
  }
}

/// ERC-4337 `userOp.signature` = `abi.encode(PublicKey, StatefulSignature,
/// bytes ecdsaSig)` — the SHRINCS structs plus the owner's ECDSA co-signature
/// over the wallet's `quipUserOpHashEcdsaTarget(userOpHash)` (the hybrid gate:
/// `_validateSignature` requires BOTH keys).
export function encodeUserOpSignature(
  publicKey: ShrincsPublicKey,
  signature: StatefulSignature,
  ecdsaSig: Hex
): Hex {
  return encodeAbiParameters(
    [PUBLIC_KEY_TUPLE, STATEFUL_SIGNATURE_TUPLE, { name: "ecdsaSig", type: "bytes" }],
    [publicKeyToAbi(publicKey), signature, ecdsaSig]
  );
}

export function decodeUserOpSignature(blob: Hex): {
  publicKey: ShrincsPublicKey;
  signature: StatefulSignature;
  ecdsaSig: Hex;
} {
  const [pk, signature, ecdsaSig] = decodeAbiParameters(
    [PUBLIC_KEY_TUPLE, STATEFUL_SIGNATURE_TUPLE, { name: "ecdsaSig", type: "bytes" }],
    blob
  ) as unknown as [Parameters<typeof publicKeyFromAbi>[0], StatefulSignature, Hex];
  return { publicKey: publicKeyFromAbi(pk), signature, ecdsaSig };
}

/// Paymaster sponsorship blob (the tail of `paymasterAndData`) =
/// `abi.encode(PublicKey, StatefulSignature)`. The global sponsorship key has
/// no ECDSA co-signer (paymaster admin authority is owner-fiat), so this keeps
/// the plain pair layout — mirrors `Codec.decodeSponsorshipSignature`.
export function encodeSponsorshipSignature(
  publicKey: ShrincsPublicKey,
  signature: StatefulSignature
): Hex {
  return encodeAbiParameters(
    [PUBLIC_KEY_TUPLE, STATEFUL_SIGNATURE_TUPLE],
    [publicKeyToAbi(publicKey), signature]
  );
}

export function decodeSponsorshipSignature(blob: Hex): {
  publicKey: ShrincsPublicKey;
  signature: StatefulSignature;
} {
  const [pk, signature] = decodeAbiParameters(
    [PUBLIC_KEY_TUPLE, STATEFUL_SIGNATURE_TUPLE],
    blob
  ) as unknown as [Parameters<typeof publicKeyFromAbi>[0], StatefulSignature];
  return { publicKey: publicKeyFromAbi(pk), signature };
}

/// Standalone abi-encoded `SHRINCS.PublicKey` tuple — the `SHRINCS_VERIFIER_PUBLIC_KEY`
/// env format the deploy scripts `abi.decode` into the Solidity struct
/// (`ShrincsPaymaster.initialize` derives the commitment + leaf budget from it).
export function encodePublicKeyBundle(publicKey: ShrincsPublicKey): Hex {
  return encodeAbiParameters([PUBLIC_KEY_TUPLE], [publicKeyToAbi(publicKey)]);
}

/// The digest a `verifyUpgrade` probe vector signs: the upgrade target address
/// hashed as a single 32-byte word. Mirrors `ShrincsWalletCodec.probeDigest`
/// (`EfficientHashLib.hash(uint256(uint160(newImplementation)))`) — it binds the
/// probe to the implementation being upgraded to, and the wallet RECOMPUTES it,
/// so the vector never carries it.
export function probeDigest(newImplementation: Address): Hex {
  return keccak256(
    encodeAbiParameters([{ type: "uint256" }], [BigInt(newImplementation)])
  );
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*              STATELESS FIXED LAYOUT (hashsigs 0.4.0)        */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

/// The stateless signature in the verifier's fixed layout (`StatelessLayout`'s
/// PQ section): `FORS ‖ hypertree`, a flat concatenation with no offsets or
/// length words.
///
///   FORS      = randomizer ‖ counter(u32 BE) ‖ entry…   entry = secretLeaf ‖ authPath…
///   hypertree = layer…   layer = wotsCPkHash ‖ randomizer ‖ counter(u32 BE) ‖ chains… ‖ authPath…
///
/// This is what `recoverWallet`, `transferOwnership` and the `verifyUpgrade`
/// probe take as `bytes`, and the tail of the ERC-1271 envelope. Throws if the
/// result is not exactly `STATELESS_PQ_BYTES` long, which catches any struct
/// with a missing, extra or mis-sized node before it reaches the chain.
export function encodeStatelessSignature(signature: StatelessSignature): Hex {
  const u32 = (n: number): Hex => toHex(n, { size: 4 });
  const pq = concat([
    signature.fors.randomizer,
    u32(signature.fors.counter),
    ...signature.fors.entries.flatMap((entry) => [
      entry.secretLeaf,
      ...entry.authPath,
    ]),
    ...signature.hypertree.flatMap((layer) => [
      layer.wotsCPkHash,
      layer.wotsCSignature.randomizer,
      u32(layer.wotsCSignature.counter),
      ...layer.wotsCSignature.chains,
      ...layer.authPath,
    ]),
  ]);
  if (size(pq) !== STATELESS_PQ_BYTES) {
    throw new StatelessEncodingLengthError(
      "statelessSignature",
      STATELESS_PQ_BYTES,
      size(pq)
    );
  }
  return pq;
}

/// The verifier's stateless payload `PK ‖ PQ`, with
/// `PK = statefulPublicKey ‖ publicKeyCommitment ‖ pkSeed ‖ hypertreeRoot`.
/// Mirrors `ShrincsWalletCodec.tryEncodeStatelessPayload`; throws where the
/// contract rejects (a key field of the wrong width).
export function encodeStatelessPayload(
  publicKey: ShrincsPublicKey,
  signature: StatelessSignature
): Hex {
  const pk = concat([
    publicKey.statefulPublicKey,
    publicKey.publicKeyCommitment,
    publicKey.pkSeed,
    publicKey.hypertreeRoot,
  ]);
  if (
    size(publicKey.statefulPublicKey) !== STATELESS_PK_BYTES - 96 ||
    size(publicKey.publicKeyCommitment) !== 32 ||
    size(publicKey.pkSeed) !== 32 ||
    size(publicKey.hypertreeRoot) !== 32
  ) {
    throw new StatelessEncodingLengthError(
      "statelessPublicKey",
      STATELESS_PK_BYTES,
      size(pk)
    );
  }
  return concat([pk, encodeStatelessSignature(signature)]);
}

/// The bare `verifyUpgrade` probe vector = `abi.encode(PublicKey bundle,
/// StatefulSignature statefulSig, bytes statelessSig)` — the frozen `IWallet`
/// seam a throwaway bundle presents so `verifyUpgrade` can confirm the target
/// implementation speaks this signing scheme. `statelessSig` is the fixed-layout
/// PQ section. Head word[0] == 0x60 (three tail offsets), the shape the wallet's
/// shape-sniff reads as "bare vector" (vs 0xc0 for a full auth blob it must
/// unwrap first).
export function encodeProbeVector(params: {
  bundle: ShrincsPublicKey;
  statefulSig: StatefulSignature;
  statelessSig: StatelessSignature;
}): Hex {
  return encodeAbiParameters(
    [PUBLIC_KEY_TUPLE, STATEFUL_SIGNATURE_TUPLE, { type: "bytes" }],
    [
      publicKeyToAbi(params.bundle),
      params.statefulSig,
      encodeStatelessSignature(params.statelessSig),
    ]
  );
}

/// UUPS `upgradeToAndCall` data = `abi.encode(PublicKey, StatefulSignature,
/// bool shouldMigrate, bytes migratorPayload, uint256 nonce, bytes probePayload)`.
/// Head word[0] == 0xc0 (six words), the shape the wallet's `verifyUpgrade`
/// shape-sniff reads as "full auth blob" and unwraps to reach `probePayload`.
///
/// The 6th field, `probePayload`, is the bare `encodeProbeVector` output the
/// wallet forwards to the NEW implementation's `verifyUpgrade` — a reachability
/// probe of the target's signing scheme, distinct from the caller's own auth
/// signature (fields 1-2). This one blob works for BOTH the deployed
/// V1.0.1-beta.2 caller (whose 5-field decoder reads fields 1-5 and forwards the
/// WHOLE blob to the probe) and later callers (which read all 6 fields directly).
///
/// The signed action nonce rides in the blob (5th head word) so the probe can
/// rebuild the exact signed context both before and after consumption;
/// `upgradeToAndCall` requires it to equal the live `actionNonce()` (else
/// `StaleActionNonce`).
export function encodeUpgradeData(params: {
  publicKey: ShrincsPublicKey;
  signature: StatefulSignature;
  shouldMigrate: boolean;
  migratorPayload: Hex;
  nonce: bigint;
  probePayload: Hex;
}): Hex {
  return encodeAbiParameters(
    [
      PUBLIC_KEY_TUPLE,
      STATEFUL_SIGNATURE_TUPLE,
      { name: "shouldMigrate", type: "bool" },
      { name: "migratorPayload", type: "bytes" },
      { name: "nonce", type: "uint256" },
      { name: "probePayload", type: "bytes" },
    ],
    [
      publicKeyToAbi(params.publicKey),
      params.signature,
      params.shouldMigrate,
      params.migratorPayload,
      params.nonce,
      params.probePayload,
    ]
  );
}

/// ERC-1271 signature in the wallet's fixed-layout envelope:
///
///   MAGIC "QPCS" (4) ‖ VERSION (1) ‖ PROFILE_ID (32) ‖ owner ECDSA (65) ‖ PK ‖ PQ
///
/// 29,358 bytes on the 256s profile. Mirrors the layout in
/// `ShrincsWalletCodec` ("ERC-1271 ENVELOPE LAYOUT"). The trailing `PK ‖ PQ` is
/// `encodeStatelessPayload`, forwarded unchanged to the verifier.
export function encodeErc1271Signature(params: {
  publicKey: ShrincsPublicKey;
  signature: StatelessSignature;
  ecdsaSig: Hex;
}): Hex {
  if (size(params.ecdsaSig) !== ERC1271_ECDSA_BYTES) {
    throw new StatelessEncodingLengthError(
      "erc1271EcdsaSignature",
      ERC1271_ECDSA_BYTES,
      size(params.ecdsaSig)
    );
  }
  const envelope = concat([
    ERC1271_MAGIC,
    toHex(ERC1271_VERSION, { size: 1 }),
    SHRINCS_PROFILE_ID,
    params.ecdsaSig,
    encodeStatelessPayload(params.publicKey, params.signature),
  ]);
  if (size(envelope) !== ERC1271_SIGNATURE_BYTES) {
    throw new StatelessEncodingLengthError(
      "erc1271Signature",
      ERC1271_SIGNATURE_BYTES,
      size(envelope)
    );
  }
  return envelope;
}

/// The ERC-1271 signature the frozen V1.0.1-beta.2 generation accepts:
/// `abi.encode(PublicKey, StatelessSignature, bytes ecdsaSig)`. Wallets on a
/// later generation reject it; use `encodeErc1271Signature`.
export function encodeLegacyErc1271Signature(params: {
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

/// Lifetime identity of a stateful tree: `keccak256(pkSeed ‖ root)` over the
/// first 64 bytes of the 68-byte encoded stateful public key. The trailing
/// `maxSignatures` is deliberately excluded — re-declaring the budget does not
/// make a new tree. Mirrors `ShrincsWallet._statefulTreeId`.
export function statefulTreeId(statefulPublicKey: Hex): Hex {
  const n = size(statefulPublicKey);
  if (n !== 68) {
    throw new Error(`statefulPublicKey must be 68 bytes, got ${n}`);
  }
  return keccak256(sliceHex(statefulPublicKey, 0, 64));
}

/// The signing budget a 68-byte encoded stateful public key declares: its
/// trailing big-endian `uint32` (`pkSeed(32) ‖ root(32) ‖ maxSignatures(4)`).
/// Mirrors `UXMSS.decodeStatefulPublicKey(...).maxSignatures`.
export function statefulMaxSignatures(statefulPublicKey: Hex): number {
  const bytes = hexToBytes(statefulPublicKey);
  if (bytes.length !== 68) {
    throw new Error(
      `statefulPublicKey must be 68 bytes, got ${bytes.length}`
    );
  }
  return (
    ((bytes[64] << 24) | (bytes[65] << 16) | (bytes[66] << 8) | bytes[67]) >>> 0
  );
}

/// Lifetime identity of a stateless tree: `keccak256(pkSeed ‖ hypertreeRoot)`
/// over the first 32 bytes of each field. Mirrors `ShrincsWallet._statelessTreeId`.
export function statelessTreeId(pkSeed: Hex, hypertreeRoot: Hex): Hex {
  const seedN = size(pkSeed);
  const rootN = size(hypertreeRoot);
  if (seedN !== 32 || rootN !== 32) {
    throw new Error(
      `pkSeed and hypertreeRoot must be 32 bytes, got ${seedN} and ${rootN}`
    );
  }
  return keccak256(
    concat([sliceHex(pkSeed, 0, 32), sliceHex(hypertreeRoot, 0, 32)])
  );
}

/// Build the `StatefulRotationTarget` for `rotateKey` from a fresh stateful
/// public key, reusing the current bundle's stateless half. `publicKeyCommitment`
/// is derived to match the on-chain commitment formula.
export function buildStatefulRotationTarget(params: {
  nextStatefulPublicKey: Hex;
  currentPkSeed: Hex;
  currentHypertreeRoot: Hex;
}): StatefulRotationTarget {
  return {
    statefulPublicKey: params.nextStatefulPublicKey,
    publicKeyCommitment: publicKeyCommitment({
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
