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
  bytesToHex,
  concat,
  decodeAbiParameters,
  encodeAbiParameters,
  hexToBytes,
  keccak256,
  pad,
  toBytes,
  toHex,
} from "viem";

import { shrincsWalletAbi } from "./abi/ShrincsWallet.js";
import { HASH_SUITE_KECCAK_256 } from "./constants.js";
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

const PUBLIC_KEY_TUPLE = findStructTuple("struct SHRINCS.PublicKey");
const STATEFUL_SIGNATURE_TUPLE = findStructTuple("struct SHRINCS.Signature");
const STATELESS_SIGNATURE_TUPLE = findStructTuple("struct SPHINCSPlusC.Signature");

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

/// Factory init payload: `abi.encode(bytes32 commitment, bytes32 pkSeed,
/// PublicKey, uint32 hashSuite, bytes32 erc1271Commitment, uint32
/// erc1271HashSuite)`. Both suites default to keccak-256 — the only suite the
/// wallet accepts.
export function encodeInitPayload(params: {
  mainBundle: ShrincsPublicKey;
  erc1271Commitment: Hex;
  hashSuite?: number;
  erc1271HashSuite?: number;
}): Hex {
  const commitment = params.mainBundle.publicKeyCommitment;
  const pkSeed = params.mainBundle.pkSeed;
  return encodeAbiParameters(
    [
      { name: "commitment", type: "bytes32" },
      { name: "pkSeed", type: "bytes32" },
      PUBLIC_KEY_TUPLE,
      { name: "hashSuite", type: "uint32" },
      { name: "erc1271Commitment", type: "bytes32" },
      { name: "erc1271HashSuite", type: "uint32" },
    ],
    [
      commitment,
      pkSeed,
      publicKeyToAbi(params.mainBundle),
      params.hashSuite ?? HASH_SUITE_KECCAK_256,
      params.erc1271Commitment,
      params.erc1271HashSuite ?? HASH_SUITE_KECCAK_256,
    ]
  );
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

/// UUPS `upgradeToAndCall` data = `abi.encode(PublicKey, StatefulSignature,
/// bool shouldMigrate, bytes migratorPayload, uint256 nonce)`. The signed
/// action nonce rides in the blob (5th head word) so the wallet's
/// `verifyUpgrade` probe can rebuild the exact signed context both before and
/// after consumption; `upgradeToAndCall` requires it to equal the live
/// `actionNonce()` (else `StaleActionNonce`).
export function encodeUpgradeData(params: {
  publicKey: ShrincsPublicKey;
  signature: StatefulSignature;
  shouldMigrate: boolean;
  migratorPayload: Hex;
  nonce: bigint;
}): Hex {
  return encodeAbiParameters(
    [
      PUBLIC_KEY_TUPLE,
      STATEFUL_SIGNATURE_TUPLE,
      { name: "shouldMigrate", type: "bool" },
      { name: "migratorPayload", type: "bytes" },
      { name: "nonce", type: "uint256" },
    ],
    [
      publicKeyToAbi(params.publicKey),
      params.signature,
      params.shouldMigrate,
      params.migratorPayload,
      params.nonce,
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
/// Lifetime identity of a stateful tree: `keccak256(pkSeed ‖ root)` over the
/// first 64 bytes of the 68-byte encoded stateful public key. The trailing
/// `maxSignatures` is deliberately excluded — re-declaring the budget does not
/// make a new tree. Mirrors `ShrincsWallet._statefulTreeId`.
export function statefulTreeId(statefulPublicKey: Hex): Hex {
  const bytes = hexToBytes(statefulPublicKey);
  if (bytes.length !== 68) {
    throw new Error(
      `statefulPublicKey must be 68 bytes, got ${bytes.length}`
    );
  }
  return keccak256(bytes.subarray(0, 64));
}

/// Lifetime identity of a stateless tree: `keccak256(pkSeed ‖ hypertreeRoot)`
/// over the first 32 bytes of each field. Mirrors `ShrincsWallet._statelessTreeId`.
export function statelessTreeId(pkSeed: Hex, hypertreeRoot: Hex): Hex {
  const seed = hexToBytes(pkSeed);
  const root = hexToBytes(hypertreeRoot);
  if (seed.length < 32 || root.length < 32) {
    throw new Error("pkSeed and hypertreeRoot must be at least 32 bytes");
  }
  return keccak256(concat([bytesToHex(seed.subarray(0, 32)), bytesToHex(root.subarray(0, 32))]));
}

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
