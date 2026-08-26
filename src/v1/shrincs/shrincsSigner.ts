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
import { type Hex, hexToBytes, toHex } from "viem";

import { publicKeyCommitment } from "./shrincsCodec.js";
import { ShrincsKeyDerivationSelfTestError } from "./errors.js";
import {
  type ActionContext,
  type RotationContext,
  type RotationTarget,
  type ShrincsPublicKey,
  type ShrincsWasmModule,
  type StatefulSignature,
  type StatelessSignature,
  type WasmShrincsKeypair,
} from "./types.js";
import { loadShrincsWasm } from "@quip.network/hashsigs-wasm";

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
  statefulVaultId: Hex;
  statelessVaultId: Hex;
  maxSignatures: number;
}

function graftHybridPublicKey(
  statefulInner: WasmShrincsKeypair,
  statelessInner: WasmShrincsKeypair
): ShrincsPublicKey {
  // Raw wasm DTO (string leaves) → SDK DTO (Hex leaves): legal downcast; the
  // wasm always emits 0x-lowercase hex (proven by hashsigsBoundary.test.ts).
  const stateful = statefulInner.publicKey() as ShrincsPublicKey;
  const stateless = statelessInner.publicKey() as ShrincsPublicKey;
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

/// A live SHRINCS keypair handle. Wraps the WASM signing key and exposes the
/// canonical signing surface the wallet/paymaster clients need.
///
/// All signing is deterministic and does NOT track burned leaves: the on-chain
/// used-leaf bitmap is authoritative. The caller reads the lowest unused leaf
/// from chain and passes it to the `*At` methods; `authPath.length === leaf`.
export class ShrincsKeyPair {
  /// Long-lived public key bundle. Pass straight into the codec/ABI encoders and
  /// the WASM verify/message-hash entry points.
  readonly publicKey: ShrincsPublicKey;

  private readonly wasm: ShrincsWasmModule;
  private readonly statefulInner: WasmShrincsKeypair;
  private readonly statelessInner: WasmShrincsKeypair;

  constructor(
    wasm: ShrincsWasmModule,
    statefulInner: WasmShrincsKeypair,
    statelessInner: WasmShrincsKeypair = statefulInner
  ) {
    this.wasm = wasm;
    this.statefulInner = statefulInner;
    this.statelessInner = statelessInner;
    this.publicKey =
      statelessInner === statefulInner
        ? (statefulInner.publicKey() as ShrincsPublicKey)
        : graftHybridPublicKey(statefulInner, statelessInner);
  }

  /// The installed-key commitment (the on-chain identity of this bundle).
  get publicKeyCommitment(): Hex {
    return this.publicKey.publicKeyCommitment;
  }

  // ── canonical signing (message hashing delegated to the WASM) ──────────────

  /// Sign a normal stateful action at `leaf`. The WASM folds the action context
  /// into the parameter-set message structure, so the SDK never reimplements the
  /// FORS/hypertree/WOTS-C math. Used by execute / withdraw / setErc1271Key /
  /// rotateKey / upgrade / the ERC-4337 path / the owner-binding leg of
  /// transferOwnership.
  signStatefulActionAt(context: ActionContext, leaf: number): StatefulSignature {
    const message = this.statefulActionMessageHash(context);
    return this.signStatefulRawAt(message, leaf);
  }

  /// Sign a stateless action (ERC-1271). No leaf is consumed.
  signStatelessAction(context: ActionContext): StatelessSignature {
    const message = this.statelessActionMessageHash(context);
    return this.signStatelessRaw(message);
  }

  /// Sign the stateless full-bundle rotation recovery message
  /// (`recoverWallet` and the recovery leg of `transferOwnership`).
  signFullRotation(
    context: RotationContext,
    nextKey: RotationTarget
  ): StatelessSignature {
    const message = this.fullRotationMessageHash(context, nextKey);
    return this.signStatelessRaw(message);
  }

  // ── canonical message hashes (no signing) ──────────────────────────────────

  statefulActionMessageHash(context: ActionContext): Hex {
    return this.wasm.shrincsStatefulActionMessageHash(
      this.publicKeyCommitment,
      context
    ) as Hex;
  }

  statelessActionMessageHash(context: ActionContext): Hex {
    return this.wasm.shrincsStatelessActionMessageHash(
      this.publicKeyCommitment,
      context
    ) as Hex;
  }

  fullRotationMessageHash(
    context: RotationContext,
    nextKey: RotationTarget
  ): Hex {
    return this.wasm.shrincsFullRotationMessageHash(
      this.publicKeyCommitment,
      this.publicKey,
      context,
      nextKey
    ) as Hex;
  }

  // ── raw signing (for codec/userOp composition and vector parity) ───────────

  /// Deterministically sign a raw 32-byte message at `leaf`
  /// (`authPath.length === leaf`). Does not advance any internal counter.
  signStatefulRawAt(messageHex: Hex, leaf: number): StatefulSignature {
    return this.statefulInner.signStatefulRawAt(messageHex, leaf) as StatefulSignature;
  }

  signStatelessRaw(messageHex: Hex): StatelessSignature {
    return this.statelessInner.signStatelessRaw(messageHex) as StatelessSignature;
  }

  // ── verification helpers (self-test / debugging) ───────────────────────────

  verifyStatefulRaw(messageHex: Hex, signature: StatefulSignature): boolean {
    return this.wasm.shrincsVerifyStatefulRaw(
      this.publicKeyCommitment,
      this.publicKey,
      messageHex,
      signature
    );
  }

  verifyStatelessAction(
    context: ActionContext,
    signature: StatelessSignature
  ): boolean {
    return this.wasm.shrincsVerifyStatelessAction(
      this.publicKeyCommitment,
      this.publicKey,
      context,
      signature
    );
  }
}

/// In-memory SHRINCS signer keyed off a single master secret (the seed-phrase
/// analog). Every keypair the user ever uses is deterministically derived from
/// it plus a per-wallet `vaultId`:
///
///   seedHex = keccak256(keccak256(masterSecret) ‖ vaultId)
///   keypair = shrincsKeygen(seedHex, maxSignatures)
///
/// Unlike the WOTS+ `QuipSigner`, there is **no burn set**: SHRINCS is stateful
/// and the on-chain used-leaf bitmap is authoritative. The signer never tracks
/// or persists which leaves are spent; the wallet client re-reads the bitmap
/// before every operation and signs at the lowest unused leaf.
///
/// Construct via the async factory so the WASM module is loaded before any
/// signing call:
///
///   const signer = await ShrincsSigner.create(masterSecret);
export class ShrincsSigner {
  private readonly masterSecret: Uint8Array;
  private readonly wasm: ShrincsWasmModule;

  private constructor(wasm: ShrincsWasmModule, masterSecret: Uint8Array) {
    this.wasm = wasm;
    this.masterSecret = masterSecret;
  }

  /// Load the WASM signing backend and construct a signer for `masterSecret`.
  static async create(masterSecret: Uint8Array): Promise<ShrincsSigner> {
    const wasm = await loadShrincsWasm();
    return new ShrincsSigner(wasm, keccak_256(masterSecret));
  }

  /// Deterministic per-vault seed: `keccak256(masterSecret ‖ vaultId)`.
  deriveSeedHex(vaultId: Hex): Hex {
    const seed = Uint8Array.from([
      ...this.masterSecret,
      ...hexToBytes(vaultId),
    ]);
    return toHex(keccak_256(seed));
  }

  /// Recover (re-derive) the keypair for a vault branch. The canonical path:
  /// read the wallet's `maxSignatures()` from chain, pass it here, sign. Runs
  /// the self-test before returning.
  recoverKeyPair(vaultId: Hex, opts: ShrincsKeygenOptions): ShrincsKeyPair {
    return this.keygenFromSeedHex(this.deriveSeedHex(vaultId), opts);
  }

  deriveKeyPair(params: DeriveKeyPairParams): ShrincsKeyPair {
    const statefulInner = this.wasm.shrincsKeygen(
      this.deriveSeedHex(params.statefulVaultId),
      params.maxSignatures
    );
    const statelessInner =
      params.statelessVaultId === params.statefulVaultId
        ? statefulInner
        : this.wasm.shrincsKeygen(
            this.deriveSeedHex(params.statelessVaultId),
            params.maxSignatures
          );
    const pair = new ShrincsKeyPair(this.wasm, statefulInner, statelessInner);
    this.runSelfTest(pair);
    return pair;
  }

  /// Low-level keygen from explicit seed material. Used for recovering keys
  /// whose seed is held out-of-band. Runs the self-test before returning.
  keygenFromSeedHex(seedHex: Hex, opts: ShrincsKeygenOptions): ShrincsKeyPair {
    const inner = this.wasm.shrincsKeygen(seedHex, opts.maxSignatures);
    const pair = new ShrincsKeyPair(this.wasm, inner);
    this.runSelfTest(pair);
    return pair;
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
