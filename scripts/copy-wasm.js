// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copies the vendored hashsigs-rs SHRINCS WASM artifacts into the compiled
// output. `tsc` only emits the TypeScript sources, so the wasm-bindgen `.js`
// glue, the `.wasm` binaries, the `.d.ts`, and the nodejs CommonJS sentinel
// must be copied verbatim alongside the built loader.

import { cpSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "src/v1/shrincs/wasm");
const dest = join(root, "dist/src/v1/shrincs/wasm");

if (!existsSync(src)) {
  console.error(`copy-wasm: source not found at ${src}`);
  process.exit(1);
}

cpSync(src, dest, { recursive: true });
console.log(`copy-wasm: copied ${src} -> ${dest}`);
