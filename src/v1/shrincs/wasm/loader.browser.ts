// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Browser loader for the vendored SHRINCS WASM. Uses the `web/` wasm-bindgen
// target (pure ESM — no Node builtins) and instantiates from the base64-inlined
// wasm bytes (`web/inline.ts`). Inlining makes the SDK consumable by ANY
// frontend bundler with zero config: there is no `.wasm` asset to emit or
// resolve (the `new URL(..., import.meta.url)` asset pattern is unreliable
// across bundlers and library builds). Selected over `loader.node.ts` by the
// package `"browser"` field.

import init, * as wasm from "./web/hashsigs_rs.js";
import { wasmBase64 } from "./web/inline.js";

import { type ShrincsWasmModule } from "./types.js";

let cached: ShrincsWasmModule | undefined;
let bytes: Uint8Array | undefined;

export interface BrowserWasmInit {
  /// Override the wasm source (URL, Request, Response, or bytes). Omit to use
  /// the bundled, base64-inlined wasm — no asset emission required.
  moduleOrPath?: unknown;
}

function inlineBytes(): Uint8Array {
  if (!bytes) {
    // `atob` is available in browsers and Node >= 16.
    const bin = atob(wasmBase64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    bytes = out;
  }
  return bytes;
}

/// Initialize and return the SHRINCS WASM bindings (cached). Must be awaited.
export async function loadShrincsWasm(
  opts?: BrowserWasmInit
): Promise<ShrincsWasmModule> {
  if (cached) return cached;
  const source = opts?.moduleOrPath ?? inlineBytes();
  await init({ module_or_path: source } as never);
  cached = wasm as unknown as ShrincsWasmModule;
  return cached;
}
