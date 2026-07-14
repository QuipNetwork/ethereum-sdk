// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  decodeAbiParameters,
  keccak256,
  sliceHex,
  toHex,
} from "viem";

import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import * as Codec from "../shrincsCodec.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";

const WALLET = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const CHAIN_ID = 31337;
const EMPTY_DATA_HASH = keccak256("0x");
const MAX_SIG = 8;
const seed = (s: string) => toHex(new TextEncoder().encode(s));

let mainKey: ShrincsKeyPair;
let erc1271Key: ShrincsKeyPair;

beforeAll(async () => {
  const signer = await ShrincsSigner.create(new TextEncoder().encode("codec-test"));
  mainKey = signer.keygenFromSeedHex(seed("shrincs codec main key seed"), {
    maxSignatures: MAX_SIG,
  });
  erc1271Key = signer.keygenFromSeedHex(seed("shrincs codec erc1271 key seed"), {
    maxSignatures: MAX_SIG,
  });
});

describe("shrincsCodec", () => {
  it("publicKeyCommitment matches the wasm keygen's own commitment (preimage parity)", () => {
    // The TS keccak preimage ("shrincs-public-key" ‖ statefulPublicKey ‖ pkSeed
    // ‖ hypertreeRoot) must reproduce exactly what the Rust keygen computed.
    for (const key of [mainKey, erc1271Key]) {
      expect(
        Codec.publicKeyCommitment({
          statefulPublicKey: key.publicKey.statefulPublicKey,
          pkSeed: key.publicKey.pkSeed,
          hypertreeRoot: key.publicKey.hypertreeRoot,
        })
      ).toBe(key.publicKeyCommitment);
    }
  });

  it("buildStatefulRotationTarget derives the on-chain next commitment", () => {
    // `rotateKey` grafts a FRESH stateful subkey onto the CURRENT bundle's
    // stateless root. This test needs some second stateful public key to play
    // the "fresh subkey" role; rather than paying for a third SPHINCS keygen,
    // it borrows the stateful half of the erc1271 keypair generated in
    // `beforeAll`.
    const target = Codec.buildStatefulRotationTarget({
      nextStatefulPublicKey: erc1271Key.publicKey.statefulPublicKey,
      currentPkSeed: mainKey.publicKey.pkSeed,
      currentHypertreeRoot: mainKey.publicKey.hypertreeRoot,
    });
    expect(target.statefulPublicKey).toBe(erc1271Key.publicKey.statefulPublicKey);
    expect(target.publicKeyCommitment).toBe(
      Codec.publicKeyCommitment({
        statefulPublicKey: erc1271Key.publicKey.statefulPublicKey,
        pkSeed: mainKey.publicKey.pkSeed,
        hypertreeRoot: mainKey.publicKey.hypertreeRoot,
      })
    );
    // Grafting changed the stateful half, so the commitment must move.
    expect(target.publicKeyCommitment).not.toBe(mainKey.publicKeyCommitment);
  });

  it("domain separator binds tag, chainId, and address", () => {
    const base = Codec.domainSeparator(CHAIN_ID, WALLET);
    expect(base).toMatch(/^0x[0-9a-f]{64}$/);
    expect(Codec.domainSeparator(CHAIN_ID, WALLET)).toBe(base); // deterministic
    expect(Codec.domainSeparator(CHAIN_ID + 1, WALLET)).not.toBe(base);
    expect(
      Codec.domainSeparator(CHAIN_ID, "0x000000000000000000000000000000000000dEaD")
    ).not.toBe(base);
    expect(
      Codec.domainSeparator(CHAIN_ID, WALLET, keccak256(toHex("other-tag")))
    ).not.toBe(base);
  });

  it("payload hashes bind every field", () => {
    const target = "0x00000000000000000000000000000000000000b0" as Address;
    const exec = Codec.executePayloadHash(target, 0n, EMPTY_DATA_HASH, 0n);
    expect(Codec.executePayloadHash(target, 1n, EMPTY_DATA_HASH, 0n)).not.toBe(exec);
    expect(Codec.executePayloadHash(target, 0n, keccak256("0x01"), 0n)).not.toBe(exec);
    expect(Codec.executePayloadHash(target, 0n, EMPTY_DATA_HASH, 1n)).not.toBe(exec);

    const withdraw = Codec.withdrawPayloadHash(target, 5n);
    expect(Codec.withdrawPayloadHash(target, 6n)).not.toBe(withdraw);

    const upgrade = Codec.upgradePayloadHash(target, false, EMPTY_DATA_HASH);
    expect(Codec.upgradePayloadHash(target, true, EMPTY_DATA_HASH)).not.toBe(upgrade);

    const setKey = Codec.setErc1271KeyPayloadHash(mainKey.publicKeyCommitment);
    expect(setKey).toBe(
      Codec.setErc1271KeyPayloadHash(mainKey.publicKeyCommitment, HASH_SUITE_KECCAK_256)
    );
    expect(
      Codec.setErc1271KeyPayloadHash(erc1271Key.publicKeyCommitment)
    ).not.toBe(setKey);

    // rotateKeyPayloadHash is the single-word EfficientHashLib.hash(commitment).
    expect(Codec.rotateKeyPayloadHash(mainKey.publicKeyCommitment)).toBe(
      keccak256(mainKey.publicKeyCommitment)
    );
  });

  it("encodeInitPayload matches the wallet decodeInit head layout", () => {
    const payload = Codec.encodeInitPayload({
      mainBundle: mainKey.publicKey,
      erc1271Commitment: erc1271Key.publicKeyCommitment,
    });
    // Fixed 6-word head: commitment ‖ pkSeed ‖ PublicKey offset ‖ hashSuite ‖
    // erc1271Commitment ‖ erc1271HashSuite (what `Codec.decodeInit` slices).
    const word = (i: number): Hex => sliceHex(payload, i * 32, (i + 1) * 32);
    expect(word(0)).toBe(mainKey.publicKeyCommitment);
    expect(word(1)).toBe(mainKey.publicKey.pkSeed);
    expect(BigInt(word(3))).toBe(BigInt(HASH_SUITE_KECCAK_256));
    expect(word(4)).toBe(erc1271Key.publicKeyCommitment);
    expect(BigInt(word(5))).toBe(BigInt(HASH_SUITE_KECCAK_256));
    // The embedded PublicKey tuple decodes back to the main bundle.
    const [, , pk] = decodeAbiParameters(
      [
        { name: "commitment", type: "bytes32" },
        { name: "pkSeed", type: "bytes32" },
        Codec.abiTuples.publicKey,
        { name: "hashSuite", type: "uint32" },
        { name: "erc1271Commitment", type: "bytes32" },
        { name: "erc1271HashSuite", type: "uint32" },
      ],
      payload
    );
    expect(pk).toEqual(Codec.publicKeyToAbi(mainKey.publicKey));
  });

  it("round-trips the userOp.signature ABI blob with a live signature", () => {
    const message = keccak256(toHex("codec blob message"));
    const signature = mainKey.signStatefulRawAt(message, 3);
    expect(signature.authPath.length).toBe(3);

    const blob = Codec.encodeUserOpSignature(mainKey.publicKey, signature);
    const decoded = Codec.decodeUserOpSignature(blob);

    expect(decoded.publicKey).toEqual(mainKey.publicKey);
    expect(decoded.signature).toEqual(signature);
    // The decoded signature still verifies against the original message.
    expect(mainKey.verifyStatefulRaw(message, decoded.signature)).toBe(true);
  });
});
