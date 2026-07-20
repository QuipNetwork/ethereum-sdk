// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Boundary test for the published hashsigs-wasm package. What's proven HERE:
// the module loads, the raw surface behaves, every output leaf honors the
// 0x-lowercase-hex shape the string→Hex cast in ../wasm/index.ts relies on,
// and the wasm build is the exact version we audited the cast against.

import { keccak256, toHex } from "viem";

import { loadShrincsWasm } from "../wasm/index.js";

// rc1 enforces >= 32-byte seeds (ERR_SEED_TOO_SHORT), so derive via keccak.
const seed32 = (s: string) => keccak256(toHex(new TextEncoder().encode(s)));

const HEX_RE = /^0x[0-9a-f]*$/;

describe("hashsigs boundary (published @quip.network/hashsigs-wasm)", () => {
  it("loads, signs at an explicit leaf, and verifies (stateful + stateless)", async () => {
    const wasm = await loadShrincsWasm();
    const kp = wasm.shrincsKeygen(seed32("shrincs wallet main key seed"), 8);

    const message = keccak256(seed32("boundary wasm message"));
    const sig = kp.signStatefulRawAt(message, 1);
    expect(sig.authPath.length).toBe(1);
    expect(
      wasm.shrincsVerifyStatefulRaw(
        kp.publicKey().publicKeyCommitment,
        kp.publicKey(),
        message,
        sig
      )
    ).toBe(true);

    const statelessSig = kp.signStatelessRaw(message);
    expect(
      wasm.shrincsVerifyStatelessRaw(
        kp.publicKey().publicKeyCommitment,
        kp.publicKey(),
        message,
        statelessSig
      )
    ).toBe(true);
  });

  it("emits 0x-prefixed lowercase hex on every output leaf (the cast's runtime contract)", async () => {
    const wasm = await loadShrincsWasm();
    const kp = wasm.shrincsKeygen(seed32("shrincs hex shape seed"), 8);

    const assertHexDeep = (value: unknown): void => {
      if (typeof value === "string") {
        expect(value).toMatch(HEX_RE);
      } else if (Array.isArray(value)) {
        value.forEach(assertHexDeep);
      } else if (value !== null && typeof value === "object") {
        Object.values(value).forEach(assertHexDeep);
      }
    };

    assertHexDeep(kp.publicKey());
    assertHexDeep(kp.signStatefulRawAt(keccak256(seed32("hex shape msg")), 1));
    assertHexDeep(kp.signStatelessRaw(keccak256(seed32("hex shape msg"))));
  });

  it("pins the wasm build the string→Hex cast was audited against", async () => {
    const wasm = await loadShrincsWasm();
    expect(wasm.version()).toBe("0.2.0-rc1");
  });

  it("caches a single module instance", async () => {
    expect(await loadShrincsWasm()).toBe(await loadShrincsWasm());
  });
});
