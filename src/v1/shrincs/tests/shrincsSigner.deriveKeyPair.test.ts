// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { keccak_256 } from "@noble/hashes/sha3";
import { toHex, type Hex } from "viem";

import { ShrincsSigner } from "../shrincsSigner.js";
import { publicKeyCommitment } from "../shrincsCodec.js";
import { parameterSetIdToEnum } from "../constants.js";
import { type ActionContext } from "../types.js";

const MAX_SIG = 8;
const ZERO32 = ("0x" + "00".repeat(32)) as Hex;
const vid = (s: string): Hex => toHex(keccak_256(s));

describe("ShrincsSigner.deriveKeyPair", () => {
  it("reproduces recoverKeyPair when both points are equal (homogeneous)", async () => {
    const signer = await ShrincsSigner.create(new TextEncoder().encode("m"));
    const id = vid("vault");
    const derived = signer.deriveKeyPair({
      statefulVaultId: id,
      statelessVaultId: id,
      maxSignatures: MAX_SIG,
    });
    expect(derived.publicKey).toEqual(
      signer.recoverKeyPair(id, { maxSignatures: MAX_SIG }).publicKey
    );
  });

  it("grafts the stateful half from t and the stateless half from s (hybrid)", async () => {
    const signer = await ShrincsSigner.create(new TextEncoder().encode("m"));
    const sId = vid("stateless");
    const tId = vid("stateful");
    const sHalf = signer.recoverKeyPair(sId, { maxSignatures: MAX_SIG });
    const tHalf = signer.recoverKeyPair(tId, { maxSignatures: MAX_SIG });

    const hybrid = signer.deriveKeyPair({
      statefulVaultId: tId,
      statelessVaultId: sId,
      maxSignatures: MAX_SIG,
    });

    expect(hybrid.publicKey.statefulPublicKey).toBe(
      tHalf.publicKey.statefulPublicKey
    );
    expect(hybrid.publicKey.pkSeed).toBe(sHalf.publicKey.pkSeed);
    expect(hybrid.publicKey.hypertreeRoot).toBe(sHalf.publicKey.hypertreeRoot);
    expect(hybrid.publicKeyCommitment).toBe(
      publicKeyCommitment({
        parameterSetId: parameterSetIdToEnum(hybrid.parameterSetId),
        statefulPublicKey: tHalf.publicKey.statefulPublicKey,
        pkSeed: sHalf.publicKey.pkSeed,
        hypertreeRoot: sHalf.publicKey.hypertreeRoot,
      })
    );
    expect(hybrid.publicKeyCommitment).not.toBe(tHalf.publicKeyCommitment);
    expect(hybrid.publicKeyCommitment).not.toBe(sHalf.publicKeyCommitment);
  });

  it("signs and verifies a hybrid key on both the stateful and stateless paths", async () => {
    const signer = await ShrincsSigner.create(new TextEncoder().encode("m"));
    const hybrid = signer.deriveKeyPair({
      statefulVaultId: vid("stateful"),
      statelessVaultId: vid("stateless"),
      maxSignatures: MAX_SIG,
    });
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
});
