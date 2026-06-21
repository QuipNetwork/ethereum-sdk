// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Node loader for the vendored SHRINCS WASM. Uses the `nodejs/` wasm-bindgen
// target (CommonJS), which auto-initializes its `.wasm` synchronously on
// require. A bundler building for the browser swaps this module for
// `loader.browser.ts` via the package `"browser"` field, so the `node:module`
// import and the CJS target's `fs` access never reach a browser bundle.

import { createRequire } from "node:module";

import { type ShrincsWasmModule } from "./types.js";

let cached: ShrincsWasmModule | undefined;

/// Load the SHRINCS WASM bindings (cached). Async for a uniform API with the
/// browser loader, which must `await init()`.
export async function loadShrincsWasm(): Promise<ShrincsWasmModule> {
  if (cached) return cached;
  const require = createRequire(import.meta.url);
  cached = require("./nodejs/hashsigs_rs.js") as ShrincsWasmModule;
  return cached;
}
