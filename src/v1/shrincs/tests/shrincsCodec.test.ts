// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  concat,
  decodeAbiParameters,
  keccak256,
  sliceHex,
  toBytes,
  toHex,
} from "viem";

import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import * as Codec from "../shrincsCodec.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";

const WALLET = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const CHAIN_ID = 31337;
const EMPTY_DATA_HASH = keccak256("0x");
const MAX_SIG = 8;
// hashsigs-wasm enforces >= 32-byte seeds (ERR_SEED_TOO_SHORT) — hash the label to 32 bytes.
const seed = (s: string) => keccak256(toHex(new TextEncoder().encode(s)));

let mainKey: ShrincsKeyPair;
let erc1271Key: ShrincsKeyPair;

beforeAll(async () => {
  const signer = await ShrincsSigner.create(new TextEncoder().encode("codec-test (hd seed padding)"));
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

  it("statefulTreeId hashes pkSeed ‖ root and ignores the trailing maxSignatures", () => {
    const spk = mainKey.publicKey.statefulPublicKey;
    expect(toBytes(spk).length).toBe(68);
    expect(Codec.statefulTreeId(spk)).toBe(keccak256(sliceHex(spk, 0, 64)));
    // Re-declaring the budget changes the commitment, not the tree.
    const bytes = toBytes(spk);
    bytes[67] = (bytes[67] + 1) & 0xff;
    const rebudgeted = toHex(bytes);
    expect(rebudgeted).not.toBe(spk);
    expect(Codec.statefulTreeId(rebudgeted)).toBe(Codec.statefulTreeId(spk));
    // Distinct trees differ.
    expect(Codec.statefulTreeId(erc1271Key.publicKey.statefulPublicKey)).not.toBe(
      Codec.statefulTreeId(spk)
    );
    expect(() => Codec.statefulTreeId(sliceHex(spk, 0, 67))).toThrow(/68 bytes/);
  });

  it("statelessTreeId hashes pkSeed ‖ hypertreeRoot", () => {
    const { pkSeed, hypertreeRoot } = mainKey.publicKey;
    expect(Codec.statelessTreeId(pkSeed, hypertreeRoot)).toBe(
      keccak256(concat([sliceHex(pkSeed, 0, 32), sliceHex(hypertreeRoot, 0, 32)]))
    );
    expect(
      Codec.statelessTreeId(erc1271Key.publicKey.pkSeed, erc1271Key.publicKey.hypertreeRoot)
    ).not.toBe(Codec.statelessTreeId(pkSeed, hypertreeRoot));
    expect(() => Codec.statelessTreeId(sliceHex(pkSeed, 0, 31), hypertreeRoot)).toThrow(
      /at least 32 bytes/
    );
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

  it("rotation domain separator folds a distinct per-path tag into the base", () => {
    const base = Codec.domainSeparator(CHAIN_ID, WALLET);
    const recover = Codec.rotationDomainSeparator(
      base,
      Codec.ROTATION_DOMAIN_RECOVER_WALLET
    );
    const handover = Codec.rotationDomainSeparator(
      base,
      Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP
    );
    // Mirrors `EfficientHashLib.hash(base, tag)` on-chain.
    expect(recover).toBe(
      keccak256(concat([base, Codec.ROTATION_DOMAIN_RECOVER_WALLET]))
    );
    // The two paths must never share a rotation domain (handover→recovery downgrade).
    expect(recover).not.toBe(handover);
    expect(recover).not.toBe(base);
    expect(Codec.ROTATION_DOMAIN_RECOVER_WALLET).toBe(
      keccak256(toBytes("quip.shrincs.rotation.recoverWallet"))
    );
    expect(Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP).toBe(
      keccak256(toBytes("quip.shrincs.rotation.transferOwnership"))
    );
  });

  it("payload hashes bind every field", () => {
    const target = "0x00000000000000000000000000000000000000b0" as Address;
    const exec = Codec.executePayloadHash(target, 0n, EMPTY_DATA_HASH, 0n);
    expect(Codec.executePayloadHash(target, 1n, EMPTY_DATA_HASH, 0n)).not.toBe(exec);
    expect(Codec.executePayloadHash(target, 0n, keccak256("0x01"), 0n)).not.toBe(exec);
    // 4th field is the signer's maxFee CEILING — bound so a relayer cannot
    // raise the cap on a signed execute.
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

  it("markLeavesUsed payload binds the exact target array (content, order, length)", () => {
    // leavesHash preimage is one 32-byte word per leaf index, in order — the
    // TS image of the wallet's EfficientHashLib word buffer.
    expect(Codec.leavesHash([1, 2])).toBe(
      keccak256(concat([toHex(1n, { size: 32 }), toHex(2n, { size: 32 })]))
    );
    // The payload hash is the single-word EfficientHashLib.hash(leavesHash).
    const base = Codec.markLeavesUsedPayloadHash(Codec.leavesHash([1, 2]));
    expect(base).toBe(keccak256(Codec.leavesHash([1, 2])));
    // A signed revocation authorizes exactly its array: reorder, extend, and
    // drop must all move the hash (a submitter cannot alter the batch).
    expect(Codec.markLeavesUsedPayloadHash(Codec.leavesHash([2, 1]))).not.toBe(base);
    expect(Codec.markLeavesUsedPayloadHash(Codec.leavesHash([1, 2, 3]))).not.toBe(base);
    expect(Codec.markLeavesUsedPayloadHash(Codec.leavesHash([1]))).not.toBe(base);
  });

  it("encodeInitPayload matches the wallet decodeInit head layout", () => {
    const payload = Codec.encodeInitPayload({
      mainBundle: mainKey.publicKey,
      erc1271Bundle: erc1271Key.publicKey,
    });
    // Fixed 6-word head: commitment ‖ pkSeed ‖ mainBundle offset ‖ hashSuite ‖
    // erc1271Bundle offset ‖ erc1271HashSuite (what `Codec.decodeInit` slices).
    const word = (i: number): Hex => sliceHex(payload, i * 32, (i + 1) * 32);
    expect(word(0)).toBe(mainKey.publicKeyCommitment);
    expect(word(1)).toBe(mainKey.publicKey.pkSeed);
    expect(BigInt(word(3))).toBe(BigInt(HASH_SUITE_KECCAK_256));
    expect(BigInt(word(5))).toBe(BigInt(HASH_SUITE_KECCAK_256));
    // Both embedded PublicKey tuples decode back to their bundles.
    const [, , pk, , erc1271Pk] = decodeAbiParameters(
      [
        { name: "commitment", type: "bytes32" },
        { name: "pkSeed", type: "bytes32" },
        Codec.abiTuples.publicKey,
        { name: "hashSuite", type: "uint32" },
        Codec.abiTuples.publicKey,
        { name: "erc1271HashSuite", type: "uint32" },
      ],
      payload
    );
    expect(pk).toEqual(Codec.publicKeyToAbi(mainKey.publicKey));
    expect(erc1271Pk).toEqual(Codec.publicKeyToAbi(erc1271Key.publicKey));
  });

  it("encodeUpgradeData matches the wallet decodeUpgradeAuth head layout", () => {
    const signature = mainKey.signStatefulRawAt(keccak256(toHex("upgrade auth")), 2);
    const nonce = 7n;
    const blob = Codec.encodeUpgradeData({
      publicKey: mainKey.publicKey,
      signature,
      shouldMigrate: true,
      migratorPayload: "0xdeadbeef",
      nonce,
    });
    // Fixed 5-word head: PublicKey offset ‖ StatefulSignature offset ‖
    // shouldMigrate ‖ migratorPayload offset ‖ nonce (what
    // `Codec.decodeUpgradeAuth` slices; the nonce word is at head[4] so the
    // prior offsets are unmoved from the 4-field layout).
    const word = (i: number): Hex => sliceHex(blob, i * 32, (i + 1) * 32);
    expect(BigInt(word(2))).toBe(1n); // shouldMigrate
    expect(BigInt(word(4))).toBe(nonce); // blob-borne action nonce
    // Head offsets 0/1/3 point past the 5-word head (0xa0), not the old 4-word
    // head (0x80) — pins that consumers re-encoded for the new layout.
    expect(BigInt(word(0)) >= 0xa0n).toBe(true);
    expect(BigInt(word(1)) >= 0xa0n).toBe(true);
    expect(BigInt(word(3)) >= 0xa0n).toBe(true);
  });

  it("round-trips the userOp.signature ABI blob with a live signature", () => {
    const message = keccak256(toHex("codec blob message"));
    const signature = mainKey.signStatefulRawAt(message, 3);
    expect(signature.authPath.length).toBe(3);

    // The hybrid blob carries the owner's co-signature as an opaque third field.
    const ownerEcdsaSig = `0x${"22".repeat(65)}` as Hex;
    const blob = Codec.encodeUserOpSignature(mainKey.publicKey, signature, ownerEcdsaSig);
    const decoded = Codec.decodeUserOpSignature(blob);

    expect(decoded.publicKey).toEqual(mainKey.publicKey);
    expect(decoded.signature).toEqual(signature);
    expect(decoded.ecdsaSig).toBe(ownerEcdsaSig);
    // The decoded signature still verifies against the original message.
    expect(mainKey.verifyStatefulRaw(message, decoded.signature)).toBe(true);
  });

  it("round-trips the paymaster sponsorship blob (plain pair, no co-signature)", () => {
    const message = keccak256(toHex("sponsorship blob message"));
    const signature = mainKey.signStatefulRawAt(message, 2);

    const blob = Codec.encodeSponsorshipSignature(mainKey.publicKey, signature);
    const decoded = Codec.decodeSponsorshipSignature(blob);

    expect(decoded.publicKey).toEqual(mainKey.publicKey);
    expect(decoded.signature).toEqual(signature);
    expect(mainKey.verifyStatefulRaw(message, decoded.signature)).toBe(true);
  });
});
