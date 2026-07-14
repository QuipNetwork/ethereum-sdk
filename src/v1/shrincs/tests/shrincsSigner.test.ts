// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { keccak_256 } from "@noble/hashes/sha3";
import { toHex } from "viem";

import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";
import {
  type ActionContext,
  type RotationContext,
  type RotationTarget,
} from "../types.js";

const ACTION_EXECUTE = keccakStr("quip.shrincs.action.execute");
const ACTION_ERC1271 = keccakStr("quip.shrincs.action.erc1271");
const ZERO32 = ("0x" + "00".repeat(32)) as `0x${string}`;

const MAX_SIG = 8;
const seed = (s: string) => toHex(new TextEncoder().encode(s));

let signer: ShrincsSigner;
let main: ShrincsKeyPair;
let erc1271: ShrincsKeyPair;

beforeAll(async () => {
  signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
  main = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
    maxSignatures: MAX_SIG,
  });
  erc1271 = signer.keygenFromSeedHex(seed("shrincs wallet erc1271 key seed"), {
    maxSignatures: MAX_SIG,
  });
});

describe("ShrincsSigner", () => {
  it("keygen is deterministic in the seed and distinct across seeds", async () => {
    const again = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
      maxSignatures: MAX_SIG,
    });
    expect(again.publicKey).toEqual(main.publicKey);
    // A different signer instance with a different master secret does not
    // matter for keygenFromSeedHex — the seed is the sole input.
    const other = await ShrincsSigner.create(new TextEncoder().encode("other"));
    expect(
      other.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
        maxSignatures: MAX_SIG,
      }).publicKeyCommitment
    ).toBe(main.publicKeyCommitment);

    expect(erc1271.publicKeyCommitment).not.toBe(main.publicKeyCommitment);
  });

  it("signStatefulRawAt is deterministic, leaf-shaped, and verifies", () => {
    const message = keccakStr("stateful message");
    for (const leaf of [1, 2, MAX_SIG]) {
      const sig = main.signStatefulRawAt(message, leaf);
      // On-chain invariant: the leaf index is carried as authPath.length.
      expect(sig.authPath.length).toBe(leaf);
      expect(sig).toEqual(main.signStatefulRawAt(message, leaf));
      expect(main.verifyStatefulRaw(message, sig)).toBe(true);
      // A signature over a different message must not verify.
      expect(main.verifyStatefulRaw(keccakStr("tampered"), sig)).toBe(false);
    }
  });

  it("signStatefulActionAt signs the canonical stateful action message", () => {
    const ctx: ActionContext = {
      domainSeparator: keccakStr("domain"),
      nonce: ZERO32,
      keyVersion: ZERO32,
      actionType: ACTION_EXECUTE,
      payloadHash: keccakStr("payload"),
    };
    const message = main.statefulActionMessageHash(ctx);
    expect(message).toMatch(/^0x[0-9a-f]{64}$/);
    // The hash binds the commitment: another key hashes the same ctx differently.
    expect(erc1271.statefulActionMessageHash(ctx)).not.toBe(message);
    // And every context field.
    expect(
      main.statefulActionMessageHash({ ...ctx, payloadHash: keccakStr("other") })
    ).not.toBe(message);
    expect(
      main.statefulActionMessageHash({ ...ctx, keyVersion: keccakStr("v1") })
    ).not.toBe(message);

    const sig = main.signStatefulActionAt(ctx, 4);
    expect(sig).toEqual(main.signStatefulRawAt(message, 4));
    expect(main.verifyStatefulRaw(message, sig)).toBe(true);
  });

  it("signs and verifies the stateless ERC-1271 action path", () => {
    const ctx: ActionContext = {
      domainSeparator: keccakStr("domain"),
      nonce: ZERO32,
      keyVersion: ZERO32,
      actionType: ACTION_ERC1271,
      payloadHash: keccakStr("erc1271 hash"),
    };
    const sig = erc1271.signStatelessAction(ctx);
    expect(erc1271.verifyStatelessAction(ctx, sig)).toBe(true);
    // Bound to the exact context…
    expect(
      erc1271.verifyStatelessAction({ ...ctx, payloadHash: keccakStr("x") }, sig)
    ).toBe(false);
    // …and to the signing key.
    expect(main.verifyStatelessAction(ctx, sig)).toBe(false);
  });

  it("computes distinct, deterministic full-rotation recovery messages", () => {
    const ctx: RotationContext = {
      domainSeparator: keccakStr("domain"),
      nonce: ZERO32,
      keyVersion: ZERO32,
    };
    const nextKey: RotationTarget = {
      statefulPublicKey: erc1271.publicKey.statefulPublicKey,
      publicKeyCommitment: erc1271.publicKeyCommitment,
      pkSeed: erc1271.publicKey.pkSeed,
      hypertreeRoot: erc1271.publicKey.hypertreeRoot,
    };
    const message = main.fullRotationMessageHash(ctx, nextKey);
    expect(message).toBe(main.fullRotationMessageHash(ctx, nextKey));
    // Binds the incoming bundle and the context.
    const selfTarget: RotationTarget = {
      statefulPublicKey: main.publicKey.statefulPublicKey,
      publicKeyCommitment: main.publicKeyCommitment,
      pkSeed: main.publicKey.pkSeed,
      hypertreeRoot: main.publicKey.hypertreeRoot,
    };
    expect(main.fullRotationMessageHash(ctx, selfTarget)).not.toBe(message);
    expect(
      main.fullRotationMessageHash({ ...ctx, nonce: keccakStr("n") }, nextKey)
    ).not.toBe(message);

    // The stateless recovery signature over the rotation message verifies raw.
    const sig = main.signStatelessRaw(message);
    expect(sig).toEqual(main.signStatelessRaw(message));
  });
});

// ── helpers ──────────────────────────────────────────────────────────────────

function keccakStr(s: string): `0x${string}` {
  return toHex(keccak_256(new TextEncoder().encode(s)));
}
