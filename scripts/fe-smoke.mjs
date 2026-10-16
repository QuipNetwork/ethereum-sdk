// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// FE-consumer smoke test: bundle the built SDK for the browser with esbuild and
// assert it is consumable by a frontend bundler. This guarantees:
//   1. The package resolves for `platform: "browser"` (the `"browser"` field
//      swaps the Node wasm loader for the web one) — esbuild would otherwise
//      ERROR on the Node loader's `node:module` import.
//   2. No Node builtins (`node:module`, `createRequire`, `require("fs")`) leak
//      into the browser bundle.
//   3. The web wasm target IS in the bundle (the `.wasm` asset is emitted).

import { build } from "esbuild";
import { mkdtempSync, readFileSync, readdirSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const entryFile = join(root, "dist/src/v1/shrincs/index.js");

if (!existsSync(entryFile)) {
  console.error(`fe-smoke: built SDK not found at ${entryFile} — run \`npm run build\` first.`);
  process.exit(1);
}

const entry = `
import {
  ShrincsSigner, ShrincsCodec, ShrincsWalletClient, ShrincsPaymasterClient,
  signWalletUserOp, signPaymasterUserOp, loadShrincsWasm,
} from "./dist/src/v1/shrincs/index.js";
// Reference the public surface so nothing is tree-shaken away.
globalThis.__shrincs = {
  ShrincsSigner, ShrincsWalletClient, ShrincsPaymasterClient,
  signWalletUserOp, signPaymasterUserOp, loadShrincsWasm,
  domainSeparator: ShrincsCodec.domainSeparator,
};
`;

const outdir = mkdtempSync(join(tmpdir(), "shrincs-fe-"));

let result;
try {
  result = await build({
    stdin: { contents: entry, resolveDir: root, loader: "js" },
    bundle: true,
    platform: "browser",
    format: "esm",
    outdir,
    loader: { ".wasm": "file" },
    logLevel: "silent",
  });
} catch (err) {
  console.error("fe-smoke: esbuild FAILED to bundle the SDK for the browser:\n");
  console.error(err.message ?? err);
  process.exit(1);
}

const jsFile = readdirSync(outdir).find((f) => f.endsWith(".js"));
const code = readFileSync(join(outdir, jsFile), "utf8");

const forbidden = ["node:module", "createRequire", 'require("fs")', "require('fs')"];
const leaks = forbidden.filter((s) => code.includes(s));

// The wasm is base64-inlined, so a correct browser bundle is self-contained
// (no external `.wasm` to fetch) and large (the inlined wasm is ~500KB b64).
const selfContained = code.length > 400_000;

const checks = [
  ["bundles for platform=browser", true],
  ["no Node builtins leak into the bundle", leaks.length === 0],
  ["wasm is inlined (self-contained bundle, no asset to fetch)", selfContained],
  ["WebAssembly instantiation glue is present", code.includes("WebAssembly")],
];

let ok = true;
for (const [label, pass] of checks) {
  console.log(`  ${pass ? "✓" : "✗"} ${label}`);
  if (!pass) ok = false;
}
if (leaks.length) console.error(`  leaked: ${leaks.join(", ")}`);
if (result.warnings?.length) {
  console.log(`  (${result.warnings.length} esbuild warning(s))`);
}

if (!ok) {
  console.error("\nfe-smoke: FAILED");
  process.exit(1);
}
console.log("\nfe-smoke: OK — the SDK bundles cleanly for a frontend consumer.");
