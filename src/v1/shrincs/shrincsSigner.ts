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

import { keccak_256 } from "@noble/hashes/sha3";
import { type Address, type Hex, concat, encodeAbiParameters, hexToBytes, toHex } from "viem";

import {
  abiTuples,
  fullRotationMessageHash,
  publicKeyCommitment,
  statefulActionMessageHash,
  statefulRawMessageHash,
  statelessActionMessageHash,
  statelessRawMessageHash,
  buildOwnershipAcceptanceContext,
} from "./shrincsCodec.js";
import { ShrincsKeyDerivationSelfTestError } from "./errors.js";
import { deriveQuipSeed, mnemonicToSeed, type QuipHdPathOptions } from "./hd.js";
import {
  type ActionContext,
  type RotationContext,
  type RotationTarget,
  type ShrincsPublicKey,
  type ShrincsWasmModule,
  type StatefulSignature,
  type StatelessSignature,
} from "./types.js";
import {
  loadShrincsWasm,
  decodeStatefulEnvelope,
  decodeStatelessSignature,
  type StatefulSignatureParts,
  type StatelessSignatureParts,
} from "@quip.network/hashsigs-wasm";

const ZERO32 = ("0x" + "00".repeat(32)) as Hex;

/// Fixed sentinel context signed locally as a post-derivation self-test on
/// every fresh SHRINCS keypair. Signed via the **stateless** path so it never
/// perturbs the stateful leaf state — the keypair remains usable for its full
/// stateful budget afterwards. The sentinel signature is stack-local and
/// discarded; it never crosses the SDK boundary.
const KEY_SELFTEST_CONTEXT: ActionContext = {
  domainSeparator: toHex(
    keccak_256(new TextEncoder().encode("QUIP_SHRINCS_SELFTEST_DOMAIN_v1"))
  ),
  nonce: ZERO32,
  keyVersion: ZERO32,
  actionType: toHex(
    keccak_256(new TextEncoder().encode("QUIP_SHRINCS_SELFTEST_ACTION_v1"))
  ),
  payloadHash: toHex(
    keccak_256(new TextEncoder().encode("QUIP_SHRINCS_SELFTEST_PAYLOAD_v1"))
  ),
};

export interface ShrincsKeygenOptions {
  /// Stateful signature budget burned into the key's commitment. Must match the
  /// budget the wallet was initialized with when recovering a key for signing.
  maxSignatures: number;
}

export interface DeriveKeyPairParams {
  statefulIndex: number;
  statelessIndex: number;
  maxSignatures: number;
  /// HD path levels for the stateful half, merged over the signer's own path
  /// options. Lets a graft span two `network` levels — e.g. a paymaster whose
  /// stateless half was derived under the default network and whose stateful
  /// half is chain-scoped (`{ network: chainId }`) after a rotation.
  statefulPath?: QuipHdPathOptions;
  /// HD path levels for the stateless half; see `statefulPath`.
  statelessPath?: QuipHdPathOptions;
}

/// One derived key half at the wasm boundary: the 264-byte flat signing key
/// plus the public key decomposed from the wasm's 164-byte flat bundle.
interface ShrincsKeyMaterial {
  secretKey: Uint8Array;
  publicKey: ShrincsPublicKey;
}

/// Decompose the wasm's 164-byte flat public-key bundle:
/// `statefulPublicKey(68) ‖ publicKeyCommitment(32) ‖ pkSeed(32) ‖
/// hypertreeRoot(32)`.
function decomposeFlatPublicKey(flat: Uint8Array): ShrincsPublicKey {
  return {
    statefulPublicKey: toHex(flat.slice(0, 68)),
    publicKeyCommitment: toHex(flat.slice(68, 100)),
    pkSeed: toHex(flat.slice(100, 132)),
    hypertreeRoot: toHex(flat.slice(132, 164)),
  };
}

/// Decoded wasm envelope parts (Uint8Array leaves) → SDK DTO (Hex leaves).
function statefulSignatureFromParts(
  parts: StatefulSignatureParts
): StatefulSignature {
  return {
    randomizer: toHex(parts.randomizer),
    counter: parts.counter,
    chains: parts.chains.map((chain) => toHex(chain)),
    authPath: parts.authPath.map((node) => toHex(node)),
  };
}

function statelessSignatureFromParts(
  parts: StatelessSignatureParts
): StatelessSignature {
  return {
    fors: {
      randomizer: toHex(parts.fors.randomizer),
      counter: parts.fors.counter,
      entries: parts.fors.entries.map((entry) => ({
        secretLeaf: toHex(entry.secretLeaf),
        authPath: entry.authPath.map((node) => toHex(node)),
      })),
    },
    hypertree: parts.hypertree.map((layer) => ({
      wotsCPkHash: toHex(layer.wotsCPkHash),
      wotsCSignature: {
        randomizer: toHex(layer.wotsCSignature.randomizer),
        counter: layer.wotsCSignature.counter,
        chains: layer.wotsCSignature.chains.map((chain) => toHex(chain)),
      },
      authPath: layer.authPath.map((node) => toHex(node)),
    })),
  };
}

function graftHybridPublicKey(
  stateful: ShrincsPublicKey,
  stateless: ShrincsPublicKey
): ShrincsPublicKey {
  return {
    statefulPublicKey: stateful.statefulPublicKey,
    pkSeed: stateless.pkSeed,
    hypertreeRoot: stateless.hypertreeRoot,
    publicKeyCommitment: publicKeyCommitment({
      statefulPublicKey: stateful.statefulPublicKey,
      pkSeed: stateless.pkSeed,
      hypertreeRoot: stateless.hypertreeRoot,
    }),
  };
}

/// A live SHRINCS keypair handle. Wraps the WASM signing keys and exposes the
/// canonical signing surface the wallet/paymaster clients need.
///
/// All signing is deterministic and does NOT track burned leaves: the on-chain
/// used-leaf bitmap is authoritative. The caller reads the lowest unused leaf
/// from chain and passes it to the `*At` methods; `authPath.length === leaf`.
///
/// The wasm boundary is raw bytes: signatures come back as canonical ABI
/// envelopes and are decoded into typed DTOs here. Signing uses the RAW
/// (unbound) wasm entry points, and the V4 ERC-7913 adapter binding is
/// applied HERE (see shrincsCodec's `*RawMessageHash`) over the canonical
/// hashes — hybrid-safe, because the binding must use the grafted bundle
/// commitment, which the wasm's internally-binding entry points cannot know.
export class ShrincsKeyPair {
  /// Long-lived public key bundle. Pass straight into the codec/ABI encoders.
  readonly publicKey: ShrincsPublicKey;

  private readonly wasm: ShrincsWasmModule;
  private readonly stateful: ShrincsKeyMaterial;
  private readonly stateless: ShrincsKeyMaterial;

  constructor(
    wasm: ShrincsWasmModule,
    stateful: ShrincsKeyMaterial,
    stateless: ShrincsKeyMaterial = stateful
  ) {
    this.wasm = wasm;
    this.stateful = stateful;
    this.stateless = stateless;
    this.publicKey =
      stateless === stateful
        ? stateful.publicKey
        : graftHybridPublicKey(stateful.publicKey, stateless.publicKey);
  }

  /// The installed-key commitment (the on-chain identity of this bundle).
  get publicKeyCommitment(): Hex {
    return this.publicKey.publicKeyCommitment;
  }

  // ── canonical signing ──────────────────────────────────────────────────────

  /// Sign a normal stateful action at `leaf`. The wallet delegates stateful
  /// verification to the DEPLOYED ERC-7913 verifier, whose V4 adapter binds
  /// `statefulRawMessageHash(commitment, hash)` on top of the caller hash —
  /// so the signed digest is the canonical action hash wrapped once more in
  /// that binding. Used by execute / withdraw / setErc1271Key / rotateKey /
  /// upgrade / the ERC-4337 path / the owner-binding leg of
  /// transferOwnership.
  signStatefulActionAt(context: ActionContext, leaf: number): StatefulSignature {
    const message = statefulRawMessageHash(
      this.publicKeyCommitment,
      this.statefulActionMessageHash(context)
    );
    return this.signStatefulRawAt(message, leaf);
  }

  /// Sign a stateless action (ERC-1271). No leaf is consumed. The wallet
  /// verifies stateless signatures through the DEPLOYED ERC-7913 verifier,
  /// whose V4 adapter binds `statelessRawMessageHash(commitment, hash)` on
  /// top of the caller hash — so the signed digest is the canonical action
  /// hash wrapped once more in that binding.
  signStatelessAction(context: ActionContext): StatelessSignature {
    const message = statelessRawMessageHash(
      this.publicKeyCommitment,
      this.statelessActionMessageHash(context)
    );
    return this.signStatelessRaw(message);
  }

  /// Sign the stateless full-bundle rotation recovery message
  /// (`recoverWallet` and the recovery leg of `transferOwnership`). Like
  /// `signStatelessAction`, wrapped in the external verifier's V4
  /// `statelessRawMessageHash` binding.
  signFullRotation(
    context: RotationContext,
    nextKey: RotationTarget
  ): StatelessSignature {
    const message = statelessRawMessageHash(
      this.publicKeyCommitment,
      this.fullRotationMessageHash(context, nextKey)
    );
    return this.signStatelessRaw(message);
  }

  /// Sign the RECIPIENT's stateful half of a `transferOwnership` acceptance
  /// with THIS (incoming) bundle: `ACTION_TRANSFER_OWNERSHIP` over
  /// `(newOwner, thisCommitment)` at nonce 0 / keyVersion 0, bound to this
  /// bundle's own commitment (see `buildOwnershipAcceptanceContext`). The
  /// wallet records `leaf` as used in the new epoch when the handover lands,
  /// so this bundle's first operational signature must use a different leaf
  /// — and a bundle accepts exactly ONE handover: signing a second acceptance
  /// (another wallet, another owner) at the same leaf is a one-time-signature
  /// reuse. Keygen a fresh bundle per handover.
  signOwnershipAcceptance(
    domainSeparator: Hex,
    newOwner: Address,
    leaf: number = 1
  ): StatefulSignature {
    const ctx = buildOwnershipAcceptanceContext({
      domainSeparator,
      newOwner,
      nextCommitment: this.publicKeyCommitment,
    });
    return this.signStatefulActionAt(ctx, leaf);
  }

  // ── canonical message hashes (no signing) ──────────────────────────────────

  statefulActionMessageHash(context: ActionContext): Hex {
    return statefulActionMessageHash(this.publicKeyCommitment, context);
  }

  statelessActionMessageHash(context: ActionContext): Hex {
    return statelessActionMessageHash(this.publicKeyCommitment, context);
  }

  fullRotationMessageHash(
    context: RotationContext,
    nextKey: RotationTarget
  ): Hex {
    return fullRotationMessageHash(
      this.publicKeyCommitment,
      this.publicKey,
      context,
      nextKey
    );
  }

  // ── raw signing (for codec/userOp composition and vector parity) ───────────

  /// Deterministically sign a raw 32-byte message at `leaf`
  /// (`authPath.length === leaf`). Does not advance any internal counter.
  signStatefulRawAt(messageHex: Hex, leaf: number): StatefulSignature {
    const envelope = this.wasm.shrincsSignStatefulRawAt(
      hexToBytes(messageHex),
      this.stateful.secretKey,
      leaf
    );
    return statefulSignatureFromParts(
      decodeStatefulEnvelope(envelope).signature
    );
  }

  signStatelessRaw(messageHex: Hex): StatelessSignature {
    const signature = this.wasm.shrincsSignStateless(
      hexToBytes(messageHex),
      this.stateless.secretKey
    );
    return statelessSignatureFromParts(decodeStatelessSignature(signature));
  }

  // ── verification helpers (self-test / debugging) ───────────────────────────

  verifyStatefulRaw(messageHex: Hex, signature: StatefulSignature): boolean {
    return verifyStatefulEnvelope(this.wasm, this.publicKey, messageHex, signature);
  }

  /// Verify a raw stateful signature by ANY bundle (not necessarily this one)
  /// — e.g. the incoming bundle's `transferOwnership` acceptance, checked by
  /// the current owner before spending their own signatures on the handover.
  verifyStatefulEnvelope(
    publicKey: ShrincsPublicKey,
    messageHex: Hex,
    signature: StatefulSignature
  ): boolean {
    return verifyStatefulEnvelope(this.wasm, publicKey, messageHex, signature);
  }

  verifyStatelessAction(
    context: ActionContext,
    signature: StatelessSignature
  ): boolean {
    // Mirrors the on-chain path: canonical action hash wrapped in the
    // external verifier's V4 raw binding.
    const message = statelessRawMessageHash(
      this.publicKeyCommitment,
      this.statelessActionMessageHash(context)
    );
    const encoded = encodeAbiParameters(
      [abiTuples.statelessSignature],
      [signature]
    );
    return this.wasm.shrincsVerifyStateless(
      hexToBytes(encoded),
      hexToBytes(message),
      hexToBytes(concat([this.publicKey.pkSeed, this.publicKey.hypertreeRoot]))
    );
  }
}

/// Raw stateful verification through the wasm: the composite
/// `PublicKey ‖ Signature` envelope, re-encoded through the codec tuples
/// (byte-identical to the wasm's own encoding), pinned against the bundle's
/// commitment exactly as the deployed ERC-7913 verifier pins it.
function verifyStatefulEnvelope(
  wasm: ShrincsWasmModule,
  publicKey: ShrincsPublicKey,
  messageHex: Hex,
  signature: StatefulSignature
): boolean {
  const envelope = encodeAbiParameters(
    [abiTuples.publicKey, abiTuples.statefulSignature],
    [publicKey, signature]
  );
  return wasm.shrincsVerifyStatefulRaw(
    hexToBytes(envelope),
    hexToBytes(messageHex),
    hexToBytes(publicKey.publicKeyCommitment)
  );
}

/// In-memory SHRINCS signer keyed off a single master seed (the seed-phrase
/// analog). Every keypair the user ever uses is deterministically derived from
/// it plus a caller-chosen `derivationIndex`:
///
///   seedHex = deriveQuipSeed(masterSeed, index, pathOptions)
///           // m/20814'/algorithm'/network'/account'/index'
///           // experimental algorithm and network QUIP by default
///   keypair = shrincsKeygen(seedHex, maxSignatures)
///
/// Unlike the WOTS+ `QuipSigner`, there is **no burn set**: SHRINCS is stateful
/// and the on-chain used-leaf bitmap is authoritative. The signer never tracks
/// or persists which leaves are spent; the wallet client re-reads the bitmap
/// before every operation and signs at the lowest unused leaf.
///
/// Construct via the async factory so the WASM module is loaded before any
/// signing call. Mnemonics enter through `fromMnemonic`:
///
///   const signer = await ShrincsSigner.create(masterSeed);
export class ShrincsSigner {
  private readonly masterSeed: Uint8Array;
  private readonly pathOptions: QuipHdPathOptions;
  private readonly wasm: ShrincsWasmModule;

  private constructor(
    wasm: ShrincsWasmModule,
    masterSeed: Uint8Array,
    pathOptions: QuipHdPathOptions
  ) {
    this.wasm = wasm;
    this.masterSeed = masterSeed;
    this.pathOptions = pathOptions;
  }

  /// Load the WASM signing backend and construct a signer whose keys derive
  /// from `masterSeed` under the QUIP HD path. `masterSeed` is any >=16-byte
  /// secret — typically the 64-byte BIP-39 seed (see `fromMnemonic`). The
  /// 16-byte minimum seed length is checked at first derivation, not at
  /// construction.
  static async create(
    masterSeed: Uint8Array,
    opts: QuipHdPathOptions = {}
  ): Promise<ShrincsSigner> {
    const wasm = await loadShrincsWasm();
    return new ShrincsSigner(wasm, Uint8Array.from(masterSeed), { ...opts });
  }

  /// Construct a signer from a BIP-39 English mnemonic (and optional
  /// passphrase). Throws ShrincsInvalidMnemonicError on a bad mnemonic.
  static async fromMnemonic(
    mnemonic: string,
    opts: QuipHdPathOptions & { passphrase?: string } = {}
  ): Promise<ShrincsSigner> {
    const { passphrase, ...pathOptions } = opts;
    return ShrincsSigner.create(
      mnemonicToSeed(mnemonic, passphrase),
      pathOptions
    );
  }

  /// Deterministic per-index keygen seed: the QUIP HD leaf at
  /// m/20814'/algorithm'/network'/account'/derivationIndex'.
  /// `pathOverride` replaces individual levels of the signer's path options for
  /// this derivation only (e.g. `{ network: chainId }` for a chain-scoped key).
  deriveSeedHex(derivationIndex: number, pathOverride?: QuipHdPathOptions): Hex {
    return deriveQuipSeed(this.masterSeed, derivationIndex, {
      ...this.pathOptions,
      ...pathOverride,
    });
  }

  /// Recover (re-derive) the keypair for a derivation index. The canonical path:
  /// read the wallet's `maxSignatures()` from chain, pass it here, sign. Runs
  /// the self-test before returning.
  recoverKeyPair(
    derivationIndex: number,
    opts: ShrincsKeygenOptions
  ): ShrincsKeyPair {
    return this.keygenFromSeedHex(this.deriveSeedHex(derivationIndex), opts);
  }

  deriveKeyPair(params: DeriveKeyPairParams): ShrincsKeyPair {
    const statefulSeed = this.deriveSeedHex(
      params.statefulIndex,
      params.statefulPath
    );
    const statelessSeed = this.deriveSeedHex(
      params.statelessIndex,
      params.statelessPath
    );
    const stateful = this.keyMaterial(statefulSeed, params.maxSignatures);
    const stateless =
      statelessSeed === statefulSeed
        ? stateful
        : this.keyMaterial(statelessSeed, params.maxSignatures);
    const pair = new ShrincsKeyPair(this.wasm, stateful, stateless);
    this.runSelfTest(pair);
    return pair;
  }

  /// Low-level keygen from explicit seed material. Used for recovering keys
  /// whose seed is held out-of-band. Runs the self-test before returning.
  keygenFromSeedHex(seedHex: Hex, opts: ShrincsKeygenOptions): ShrincsKeyPair {
    const pair = new ShrincsKeyPair(
      this.wasm,
      this.keyMaterial(seedHex, opts.maxSignatures)
    );
    this.runSelfTest(pair);
    return pair;
  }

  /// Derive one key half at the wasm boundary and pull its byte material out
  /// of the wasm handle.
  private keyMaterial(seedHex: Hex, maxSignatures: number): ShrincsKeyMaterial {
    const keys = this.wasm.shrincsKeygen(hexToBytes(seedHex), maxSignatures);
    return {
      secretKey: keys.secretKey,
      publicKey: decomposeFlatPublicKey(keys.publicKey),
    };
  }

  /// Sign + verify a fixed sentinel against the freshly derived key (stateless
  /// path — never perturbs leaf state). Throws if the round-trip fails.
  private runSelfTest(pair: ShrincsKeyPair): void {
    const sig = pair.signStatelessAction(KEY_SELFTEST_CONTEXT);
    if (!pair.verifyStatelessAction(KEY_SELFTEST_CONTEXT, sig)) {
      throw new ShrincsKeyDerivationSelfTestError(pair.publicKeyCommitment);
    }
  }
}
