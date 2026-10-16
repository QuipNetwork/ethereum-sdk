// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Boundary test for the hashsigs-wasm package. What's proven HERE: the
// module loads, the raw Uint8Array surface behaves (explicit-leaf signing is
// non-mutating and raw — no adapter digest binding), the ABI envelope
// decoders expose the field shapes shrincsSigner.ts converts to Hex DTOs,
// and the entry points the SDK relies on all exist on this wasm build.

import { hexToBytes, keccak256, toHex } from "viem";

import {
  loadShrincsWasm,
  decodeStatefulEnvelope,
  decodeStatelessSignature,
} from "@quip.network/hashsigs-wasm";

// Seeds must be exactly 32 bytes; derive via keccak.
const seed32 = (s: string) =>
  hexToBytes(keccak256(toHex(new TextEncoder().encode(s))));

const msg32 = (s: string) => seed32(s);

describe("hashsigs boundary (@quip.network/hashsigs-wasm)", () => {
  it("exposes every entry point the SDK relies on", async () => {
    const wasm = await loadShrincsWasm();
    for (const fn of [
      "shrincsKeygen",
      "shrincsSignStatefulRawAt",
      "shrincsSignAtLeaf",
      "shrincsSignStateless",
      "shrincsVerify",
      "shrincsVerifyStatefulRaw",
      "shrincsVerifyStateless",
      "shrincsImportSigningKey",
      "profileName",
      "version",
    ] as const) {
      expect(typeof wasm[fn]).toBe("function");
    }
    expect(typeof decodeStatefulEnvelope).toBe("function");
    expect(typeof decodeStatelessSignature).toBe("function");
    expect(wasm.profileName()).toBe("shrincs-256s-keccak");
  });

  it("signs at an explicit leaf without mutating the key, and raw-verifies", async () => {
    const wasm = await loadShrincsWasm();
    const keys = wasm.shrincsKeygen(seed32("shrincs wallet main key seed"), 8);
    const secretKey = keys.secretKey;
    const commitment = keys.publicKeyCommitment;
    expect(secretKey.length).toBe(264);
    expect(keys.publicKey.length).toBe(164);
    expect(commitment.length).toBe(32);

    const message = msg32("boundary wasm message");
    const envelope = wasm.shrincsSignStatefulRawAt(message, secretKey, 1);
    expect(keys.secretKey).toEqual(secretKey); // non-mutating

    const decoded = decodeStatefulEnvelope(envelope);
    expect(decoded.signature.authPath.length).toBe(1);
    expect(decoded.publicKey.publicKeyCommitment).toEqual(commitment);

    // Raw signing skips the adapter digest binding: the raw verify accepts
    // the message as-is, and the bound verify must reject it.
    expect(wasm.shrincsVerifyStatefulRaw(envelope, message, commitment)).toBe(
      true
    );
    expect(wasm.shrincsVerify(envelope, message, commitment)).toBe(false);

    // Deterministic per leaf; a different leaf is a different signature.
    expect(wasm.shrincsSignStatefulRawAt(message, secretKey, 1)).toEqual(
      envelope
    );
    const atLeafThree = wasm.shrincsSignStatefulRawAt(message, secretKey, 3);
    expect(decodeStatefulEnvelope(atLeafThree).signature.authPath.length).toBe(
      3
    );
  });

  it("signs stateless, decodes the FORS/hypertree shape, and verifies", async () => {
    const wasm = await loadShrincsWasm();
    const keys = wasm.shrincsKeygen(seed32("shrincs stateless key seed"), 8);

    const message = msg32("boundary stateless message");
    const signature = wasm.shrincsSignStateless(message, keys.secretKey);
    expect(
      wasm.shrincsVerifyStateless(signature, message, keys.statelessPublicKey)
    ).toBe(true);

    const decoded = decodeStatelessSignature(signature);
    expect(decoded.fors.entries.length).toBeGreaterThan(0);
    expect(decoded.hypertree.length).toBeGreaterThan(0);
    for (const entry of decoded.fors.entries) {
      expect(entry.secretLeaf.length).toBe(32);
    }
    for (const layer of decoded.hypertree) {
      expect(layer.wotsCPkHash.length).toBe(32);
      expect(layer.wotsCSignature.chains.length).toBeGreaterThan(0);
    }
  });
});
