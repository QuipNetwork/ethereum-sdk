// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { keccak_256 } from "@noble/hashes/sha3";
import { toHex } from "viem";

import { ShrincsSigner } from "../shrincsSigner.js";
import { type ActionContext, type RotationContext, type RotationTarget } from "../types.js";

const ACTION_EXECUTE = keccakStr("quip.shrincs.action.execute");
const ACTION_ERC4337 = keccakStr("quip.shrincs.action.erc4337Execute");
const ACTION_ERC1271 = keccakStr("quip.shrincs.action.erc1271");
const ZERO32 = ("0x" + "00".repeat(32)) as `0x${string}`;

const vectors = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "test/test_vectors/shrincs_wallet_sphincs_256s_keccak.json"),
    "utf8"
  )
) as WalletVectors;

const MAX_SIG = 8;
const seed = (s: string) => toHex(new TextEncoder().encode(s));

describe("ShrincsSigner", () => {
  it("keygen reproduces the committed main + erc1271 key bundles", async () => {
    const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
    const main = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
      maxSignatures: MAX_SIG,
    });
    expectPublicKey(main.publicKey, vectors.mainKey);

    const erc1271 = signer.keygenFromSeedHex(seed("shrincs wallet erc1271 key seed"), {
      maxSignatures: MAX_SIG,
    });
    expectPublicKey(erc1271.publicKey, vectors.erc1271Key);
  });

  it("signStatefulRawAt reproduces each stateful case signature at its pinned leaf", async () => {
    const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
    const main = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
      maxSignatures: MAX_SIG,
    });

    for (const c of ["execute", "executeEth", "executeCall", "withdraw", "rotateKey", "upgrade"] as const) {
      const v = vectors.cases[c];
      const sig = main.signStatefulRawAt(v.message, v.leaf);
      expect(sig).toEqual(v.signature);
      expect(main.verifyStatefulRaw(v.message, sig)).toBe(true);
    }

    for (const v of vectors.cases.erc4337) {
      const sig = main.signStatefulRawAt(v.message, v.leaf);
      expect(sig).toEqual(v.signature);
    }
  });

  it("computes the canonical stateful action message hash from a TS-assembled context", async () => {
    const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
    const main = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
      maxSignatures: MAX_SIG,
    });

    const exec = vectors.cases.execute;
    const ctx: ActionContext = {
      domainSeparator: vectors.domainSeparator,
      nonce: ZERO32,
      keyVersion: ZERO32,
      actionType: ACTION_EXECUTE,
      payloadHash: exec.payloadHash,
    };
    expect(main.statefulActionMessageHash(ctx)).toBe(exec.message);

    const op = vectors.cases.erc4337[0];
    const opCtx: ActionContext = {
      domainSeparator: vectors.domainSeparator,
      nonce: ZERO32,
      keyVersion: ZERO32,
      actionType: ACTION_ERC4337,
      payloadHash: op.payloadHash,
    };
    expect(main.statefulActionMessageHash(opCtx)).toBe(op.message);
  });

  it("reproduces the stateless ERC-1271 signature and its message hash", async () => {
    const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
    const erc1271 = signer.keygenFromSeedHex(seed("shrincs wallet erc1271 key seed"), {
      maxSignatures: MAX_SIG,
    });

    const v = vectors.cases.erc1271;
    const ctx: ActionContext = {
      domainSeparator: vectors.domainSeparator,
      nonce: ZERO32,
      keyVersion: ZERO32,
      actionType: ACTION_ERC1271,
      payloadHash: v.hash,
    };
    expect(erc1271.statelessActionMessageHash(ctx)).toBe(v.message);
    const sig = erc1271.signStatelessRaw(v.message);
    expect(erc1271.verifyStatelessAction(ctx, sig)).toBe(true);
  });

  it("reproduces the full-rotation recovery message (recoverWallet)", async () => {
    const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
    const main = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
      maxSignatures: MAX_SIG,
    });

    const v = vectors.cases.rotateFullKey;
    const ctx: RotationContext = {
      domainSeparator: vectors.domainSeparator,
      nonce: ZERO32,
      keyVersion: ZERO32,
    };
    const nextKey: RotationTarget = toRotationTarget(v.nextKey);
    expect(main.fullRotationMessageHash(ctx, nextKey)).toBe(v.message);
  });
});

// ── helpers / fixture types ──────────────────────────────────────────────────

function keccakStr(s: string): `0x${string}` {
  return toHex(keccak_256(new TextEncoder().encode(s)));
}

function expectPublicKey(got: VectorPublicKey, want: VectorPublicKey): void {
  expect(got.statefulPublicKey).toBe(want.statefulPublicKey);
  expect(got.publicKeyCommitment).toBe(want.publicKeyCommitment);
  expect(got.pkSeed).toBe(want.pkSeed);
  expect(got.hypertreeRoot).toBe(want.hypertreeRoot);
}

function toRotationTarget(pk: VectorPublicKey): RotationTarget {
  return {
    parameterSetId: "sphincs-256s-keccak-q20",
    statefulPublicKey: pk.statefulPublicKey,
    publicKeyCommitment: pk.publicKeyCommitment,
    pkSeed: pk.pkSeed,
    hypertreeRoot: pk.hypertreeRoot,
  };
}

type Hex = `0x${string}`;

interface VectorPublicKey {
  statefulPublicKey: Hex;
  publicKeyCommitment: Hex;
  pkSeed: Hex;
  hypertreeRoot: Hex;
}

interface StatefulCase {
  leaf: number;
  payloadHash: Hex;
  message: Hex;
  signature: { randomizer: Hex; counter: number; chains: Hex[]; authPath: Hex[] };
}

interface WalletVectors {
  domainSeparator: Hex;
  mainKey: VectorPublicKey;
  erc1271Key: VectorPublicKey;
  cases: {
    erc4337: StatefulCase[];
    execute: StatefulCase;
    executeEth: StatefulCase;
    executeCall: StatefulCase;
    withdraw: StatefulCase;
    rotateKey: StatefulCase;
    upgrade: StatefulCase;
    erc1271: { hash: Hex; message: Hex };
    rotateFullKey: { message: Hex; nextKey: VectorPublicKey };
  };
}
