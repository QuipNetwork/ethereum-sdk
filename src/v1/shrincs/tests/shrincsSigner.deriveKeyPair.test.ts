// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { keccak_256 } from "@noble/hashes/sha3";
import { toHex, type Hex } from "viem";

import { type ShrincsKeyPair, ShrincsSigner } from "../shrincsSigner.js";
import { publicKeyCommitment } from "../shrincsCodec.js";
import { type ActionContext } from "../types.js";

const MAX_SIG = 8;
const ZERO32 = ("0x" + "00".repeat(32)) as Hex;
const vid = (s: string): Hex => toHex(keccak_256(s));
const STATEFUL_INDEX = 1;
const STATELESS_INDEX = 2;

describe("ShrincsSigner.deriveKeyPair", () => {
  // Derivation is deterministic in the master seed and each derivation is a
  // full keygen + self-test, so the two halves and the grafted bundle are
  // derived once for every case below.
  let signer: ShrincsSigner;
  let sHalf: ShrincsKeyPair;
  let tHalf: ShrincsKeyPair;
  let hybrid: ShrincsKeyPair;
  beforeAll(async () => {
    signer = await ShrincsSigner.create(
      new TextEncoder().encode("m (hd seed padding)")
    );
    sHalf = signer.recoverKeyPair(STATELESS_INDEX, { maxSignatures: MAX_SIG });
    tHalf = signer.recoverKeyPair(STATEFUL_INDEX, { maxSignatures: MAX_SIG });
    hybrid = signer.deriveKeyPair({
      statefulIndex: STATEFUL_INDEX,
      statelessIndex: STATELESS_INDEX,
      maxSignatures: MAX_SIG,
    });
  });

  it("reproduces recoverKeyPair when both points are equal (homogeneous)", () => {
    const derived = signer.deriveKeyPair({
      statefulIndex: STATEFUL_INDEX,
      statelessIndex: STATEFUL_INDEX,
      maxSignatures: MAX_SIG,
    });
    expect(derived.publicKey).toEqual(tHalf.publicKey);
  });

  it("grafts the stateful half from t and the stateless half from s (hybrid)", () => {
    expect(hybrid.publicKey.statefulPublicKey).toBe(
      tHalf.publicKey.statefulPublicKey
    );
    expect(hybrid.publicKey.pkSeed).toBe(sHalf.publicKey.pkSeed);
    expect(hybrid.publicKey.hypertreeRoot).toBe(sHalf.publicKey.hypertreeRoot);
    expect(hybrid.publicKeyCommitment).toBe(
      publicKeyCommitment({
        statefulPublicKey: tHalf.publicKey.statefulPublicKey,
        pkSeed: sHalf.publicKey.pkSeed,
        hypertreeRoot: sHalf.publicKey.hypertreeRoot,
      })
    );
    expect(hybrid.publicKeyCommitment).not.toBe(tHalf.publicKeyCommitment);
    expect(hybrid.publicKeyCommitment).not.toBe(sHalf.publicKeyCommitment);
  });

  it("signs and verifies a hybrid key on both the stateful and stateless paths", () => {
    const statefulSig = hybrid.signStatefulRawAt(vid("message"), 1);
    expect(hybrid.verifyStatefulRaw(vid("message"), statefulSig)).toBe(true);

    const ctx: ActionContext = {
      domainSeparator: vid("domain"),
      nonce: ZERO32,
      keyVersion: ZERO32,
      actionType: vid("action"),
      payloadHash: vid("payload"),
    };
    const statelessSig = hybrid.signStatelessAction(ctx);
    expect(hybrid.verifyStatelessAction(ctx, statelessSig)).toBe(true);
  });

  it("scopes a key to a chain through the HD network level (one key per chain)", async () => {
    const secret = new TextEncoder().encode("m (hd seed padding)");
    const base = await ShrincsSigner.create(secret, { network: 8453 });
    const sepolia = await ShrincsSigner.create(secret, { network: 11155111 });
    const legacy = await ShrincsSigner.create(secret);

    const onBase = base.recoverKeyPair(0, { maxSignatures: MAX_SIG });
    const onSepolia = sepolia.recoverKeyPair(0, { maxSignatures: MAX_SIG });
    const onLegacy = legacy.recoverKeyPair(0, { maxSignatures: MAX_SIG });

    // Same secret and epoch, different chains: three distinct trees.
    expect(onBase.publicKeyCommitment).not.toBe(onSepolia.publicKeyCommitment);
    expect(onBase.publicKeyCommitment).not.toBe(onLegacy.publicKeyCommitment);
    expect(onSepolia.publicKeyCommitment).not.toBe(onLegacy.publicKeyCommitment);

    // Per-half path overrides reproduce the same chain-scoped key without a
    // dedicated signer instance.
    expect(
      legacy.deriveKeyPair({
        statefulIndex: 0,
        statelessIndex: 0,
        statefulPath: { network: 8453 },
        statelessPath: { network: 8453 },
        maxSignatures: MAX_SIG,
      }).publicKeyCommitment
    ).toBe(onBase.publicKeyCommitment);
  });

  it("grafts a chain-scoped stateful half onto a legacy stateless half", async () => {
    const secret = new TextEncoder().encode("m (hd seed padding)");
    const signer = await ShrincsSigner.create(secret);
    const legacyStateless = signer.recoverKeyPair(0, { maxSignatures: MAX_SIG });
    const chainStateful = signer.keygenFromSeedHex(
      signer.deriveSeedHex(0, { network: 8453 }),
      { maxSignatures: MAX_SIG }
    );

    const graft = signer.deriveKeyPair({
      statefulIndex: 0,
      statefulPath: { network: 8453 },
      statelessIndex: 0,
      // statelessPath omitted: signer's own (default) network level
      maxSignatures: MAX_SIG,
    });

    expect(graft.publicKey.statefulPublicKey).toBe(
      chainStateful.publicKey.statefulPublicKey
    );
    expect(graft.publicKey.pkSeed).toBe(legacyStateless.publicKey.pkSeed);
    expect(graft.publicKey.hypertreeRoot).toBe(
      legacyStateless.publicKey.hypertreeRoot
    );
    expect(graft.publicKeyCommitment).toBe(
      publicKeyCommitment({
        statefulPublicKey: chainStateful.publicKey.statefulPublicKey,
        pkSeed: legacyStateless.publicKey.pkSeed,
        hypertreeRoot: legacyStateless.publicKey.hypertreeRoot,
      })
    );
  });
});
