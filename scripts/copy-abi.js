#!/usr/bin/env node

/**
 * Copy ABIs from Foundry output to src/abi/ and extract bytecode.
 *
 * 1. Reads Foundry artifact JSON from out/ and extracts the ABI array,
 *    writing it as a TypeScript file with `as const` for viem type inference.
 * 2. Generates a barrel re-export file at src/abi/index.ts.
 * 3. Extracts QuipWallet bytecode, links the WOTSPlus library address,
 *    and writes src/bytecode.json.
 */

import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const OUT_DIR = join(ROOT, "out");
const ABI_DIR = join(ROOT, "src", "v1", "abi");

// camelCase helper: "QuipFactory" -> "quipFactoryAbi"
function toExportName(name) {
  return name.charAt(0).toLowerCase() + name.slice(1) + "Abi";
}

const CONTRACTS = [
  { name: "Deployer", path: "Deployer.sol/Deployer.json" },
  { name: "QuipFactory", path: "QuipFactory.sol/QuipFactory.json" },
  { name: "QuipWallet", path: "QuipWallet.sol/QuipWallet.json" },
  { name: "QuipPaymaster", path: "QuipPaymaster.sol/QuipPaymaster.json" },
];

// Hand-maintained ABIs that should appear in the barrel re-export but are
// NOT generated from a Foundry artifact. The corresponding `.ts` files
// already exist in `src/v1/abi/` and are committed to the repo; this script
// must NOT overwrite them — it only weaves their `export { ... }` lines
// into the generated `index.ts` barrel so consumers can import them via
// the same path as the generated ABIs.
//
// Current entries:
//   - EntryPointV07: re-exports `entryPoint07Abi` from `viem/account-abstraction`
//     under the name `entryPointV07Abi`. The ERC-4337 v0.7 EntryPoint is a
//     standardized singleton (canonical address
//     0x0000000071727De22E5E9d8BAf0edAc6f37da032 on every chain), not a
//     contract this repo ships, so there's no forge artifact to derive
//     from. See `src/v1/abi/EntryPointV07.ts` for the full rationale.
const EXTRA_BARREL_LINES = [
  `export { entryPointV07Abi } from "./EntryPointV07.js";`,
];

mkdirSync(ABI_DIR, { recursive: true });

const barrelLines = [];

for (const contract of CONTRACTS) {
  const artifactPath = join(OUT_DIR, contract.path);
  const artifact = JSON.parse(readFileSync(artifactPath, "utf-8"));
  const abi = artifact.abi;

  const exportName = toExportName(contract.name);
  const tsContent = `export const ${exportName} = ${JSON.stringify(abi, null, 2)} as const;\n`;

  const outPath = join(ABI_DIR, `${contract.name}.ts`);
  writeFileSync(outPath, tsContent);
  console.log(`Wrote ${outPath} (${abi.length} entries)`);

  barrelLines.push(`export { ${exportName} } from "./${contract.name}.js";`);
}

// Write barrel re-export — generated contract ABIs first, then any
// hand-maintained extras (see `EXTRA_BARREL_LINES` above).
const barrelPath = join(ABI_DIR, "index.ts");
const allBarrelLines = [...barrelLines, ...EXTRA_BARREL_LINES];
writeFileSync(barrelPath, allBarrelLines.join("\n") + "\n");
console.log(`Wrote ${barrelPath}`);

// --- Bytecode extraction ---
const addresses = JSON.parse(
  readFileSync(join(ROOT, "src", "v1", "addresses.json"), "utf-8")
);
const wotsAddress = addresses.WOTSPlus.toLowerCase().replace("0x", "");

const walletArtifact = JSON.parse(
  readFileSync(join(OUT_DIR, "QuipWallet.sol/QuipWallet.json"), "utf-8")
);
let bytecode = walletArtifact.bytecode.object;

// Replace library placeholder (__$<hash>$__) with actual WOTSPlus address
bytecode = bytecode.replace(/__\$[0-9a-fA-F]{34}\$__/g, wotsAddress);

const bytecodeOut = join(ROOT, "src", "v1", "bytecode.json");
writeFileSync(
  bytecodeOut,
  JSON.stringify({ quipWalletCreationCode: bytecode }, null, 2) + "\n"
);
console.log(`Wrote ${bytecodeOut} (${bytecode.length} hex chars)`);
