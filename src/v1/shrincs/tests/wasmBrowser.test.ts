// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Proves the BROWSER wasm code path (the `web/` wasm-bindgen target instantiated
// from the base64-inlined bytes — exactly what ships to a frontend) produces the
// same, correct results as the Node path. Combined with the esbuild FE bundle
// smoke (scripts/fe-smoke.mjs), this guarantees an FE consumer can both bundle
// AND run the SDK.

import { keccak256, toHex } from "viem";

import { loadShrincsWasm as loadBrowserWasm } from "../wasm/loader.browser.js";
import { loadShrincsWasm as loadNodeWasm } from "../wasm/index.js";

const seed = (s: string) => toHex(new TextEncoder().encode(s));

describe("browser wasm loader (web target, inlined bytes)", () => {
  it("instantiates from inlined bytes and matches the Node wasm path exactly", async () => {
    const browser = await loadBrowserWasm();
    const node = await loadNodeWasm();

    const browserKp = browser.shrincsKeygen(seed("shrincs wallet main key seed"), 8);
    const nodeKp = node.shrincsKeygen(seed("shrincs wallet main key seed"), 8);

    // Same seed => identical bundle across the two build targets.
    expect(browserKp.publicKey()).toEqual(nodeKp.publicKey());

    // Deterministic leaf signing agrees byte-for-byte and cross-verifies.
    const message = keccak256(seed("browser wasm message"));
    const sig = browserKp.signStatefulRawAt(message, 1);
    expect(sig.authPath.length).toBe(1);
    expect(sig).toEqual(nodeKp.signStatefulRawAt(message, 1));
    expect(
      browser.shrincsVerifyStatefulRaw(
        browserKp.publicKey().publicKeyCommitment,
        browserKp.publicKey(),
        message,
        sig
      )
    ).toBe(true);
    expect(
      node.shrincsVerifyStatefulRaw(
        nodeKp.publicKey().publicKeyCommitment,
        nodeKp.publicKey(),
        message,
        sig
      )
    ).toBe(true);
  });
});
