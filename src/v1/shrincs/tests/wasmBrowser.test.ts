// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Proves the BROWSER wasm code path (the `web/` wasm-bindgen target instantiated
// from the base64-inlined bytes — exactly what ships to a frontend) produces the
// same, correct results as the Node path and the committed vectors. Combined with
// the esbuild FE bundle smoke (scripts/fe-smoke.mjs), this guarantees an FE
// consumer can both bundle AND run the SDK.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { toHex } from "viem";

import { loadShrincsWasm } from "../wasm/loader.browser.js";

const vectors = JSON.parse(
  readFileSync(
    resolve(process.cwd(), "test/test_vectors/shrincs_wallet_sphincs_256s_keccak.json"),
    "utf8"
  )
) as any;

const seed = (s: string) => toHex(new TextEncoder().encode(s));

describe("browser wasm loader (web target, inlined bytes)", () => {
  it("instantiates from inlined bytes and reproduces the committed key + signature", async () => {
    const wasm = await loadShrincsWasm();
    expect(wasm.supported_parameter_sets()).toContain("sphincs-256s-keccak-q20");

    const kp = wasm.shrincsKeygen(
      "sphincs-256s-keccak-q20",
      seed("shrincs wallet main key seed"),
      8
    );
    expect(kp.publicKey().publicKeyCommitment).toBe(vectors.mainKey.publicKeyCommitment);

    const exec = vectors.cases.execute;
    const sig = kp.signStatefulRawAt(exec.message, exec.leaf);
    expect(sig).toEqual(exec.signature);
    expect(
      wasm.shrincs_verify_stateful_raw(
        "sphincs-256s-keccak-q20",
        kp.publicKey().publicKeyCommitment,
        kp.publicKey(),
        exec.message,
        sig
      )
    ).toBe(true);
  });
});
