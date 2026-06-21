// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { type Hex, keccak256 } from "viem";

import { ParameterSetId } from "../constants.js";
import * as Codec from "../shrincsCodec.js";
import { type ShrincsPublicKey, type StatefulSignature } from "../types.js";

const vectors = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "test/test_vectors/shrincs_wallet_sphincs_256s_keccak.json"),
    "utf8"
  )
) as any;

const WALLET = vectors.wallet as Hex;
const CHAIN_ID = 31337;
const EMPTY_DATA_HASH = keccak256("0x");

describe("shrincsCodec", () => {
  it("derives the wallet domain separator", () => {
    expect(Codec.domainSeparator(CHAIN_ID, WALLET)).toBe(vectors.domainSeparator);
  });

  it("reproduces every committed payload hash", () => {
    const c = vectors.cases;

    expect(Codec.executePayloadHash(c.execute.target, 0n, EMPTY_DATA_HASH, 0n)).toBe(
      c.execute.payloadHash
    );
    // executeEth value (1 ether) exceeds JS safe-integer range in the JSON, so
    // pin it explicitly rather than reading the imprecise number field.
    expect(Codec.executePayloadHash(c.executeEth.target, 10n ** 18n, EMPTY_DATA_HASH, 0n)).toBe(
      c.executeEth.payloadHash
    );
    expect(
      Codec.executePayloadHash(c.executeCall.target, 0n, keccak256(c.executeCall.data), 0n)
    ).toBe(c.executeCall.payloadHash);

    expect(Codec.withdrawPayloadHash(c.withdraw.to, 0n)).toBe(c.withdraw.payloadHash);

    expect(
      Codec.transferOwnershipPayloadHash(c.transferOwnership.newOwner, c.transferOwnership.nextCommitment)
    ).toBe(c.transferOwnership.payloadHash);

    expect(
      Codec.setErc1271KeyPayloadHash(c.setErc1271Key.newCommitment, ParameterSetId.Sphincs256sKeccakQ20)
    ).toBe(c.setErc1271Key.payloadHash);

    expect(
      Codec.rotateKeyPayloadHash(c.rotateKey.nextCommitment, ParameterSetId.Sphincs256sKeccakQ20)
    ).toBe(c.rotateKey.payloadHash);

    expect(Codec.upgradePayloadHash(c.upgrade.newImplementation, false, EMPTY_DATA_HASH)).toBe(
      c.upgrade.payloadHash
    );
    expect(Codec.upgradePayloadHash(c.upgradeMigrate.newImplementation, true, EMPTY_DATA_HASH)).toBe(
      c.upgradeMigrate.payloadHash
    );

    for (const op of c.erc4337) {
      expect(Codec.erc4337PayloadHash(op.userOpHash, 0n)).toBe(op.payloadHash);
    }
  });

  it("derives the rotateKey next commitment from the on-chain formula", () => {
    const c = vectors.cases.rotateKey;
    const target = Codec.buildStatefulRotationTarget({
      parameterSetId: "sphincs-256s-keccak-q20",
      nextStatefulPublicKey: c.nextStatefulPublicKey,
      currentPkSeed: vectors.mainKey.pkSeed,
      currentHypertreeRoot: vectors.mainKey.hypertreeRoot,
    });
    expect(target.publicKeyCommitment).toBe(c.nextCommitment);
  });

  it("round-trips the userOp.signature ABI blob", () => {
    const publicKey: ShrincsPublicKey = {
      parameterSetId: "sphincs-256s-keccak-q20",
      statefulPublicKey: vectors.mainKey.statefulPublicKey,
      publicKeyCommitment: vectors.mainKey.publicKeyCommitment,
      pkSeed: vectors.mainKey.pkSeed,
      hypertreeRoot: vectors.mainKey.hypertreeRoot,
    };
    const signature = vectors.cases.execute.signature as StatefulSignature;

    const blob = Codec.encodeUserOpSignature(publicKey, signature);
    const decoded = Codec.decodeUserOpSignature(blob);

    expect(decoded.publicKey).toEqual(publicKey);
    expect(decoded.signature).toEqual(signature);
  });
});
