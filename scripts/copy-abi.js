#!/usr/bin/env node

/**
 * Copy ABIs from Foundry output to src/abi/
 *
 * Reads the full Foundry artifact JSON from out/ and extracts just the ABI array,
 * writing it as a TypeScript file with `as const` for viem type inference.
 */

import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, "..");
const OUT_DIR = join(ROOT, "out");
const ABI_DIR = join(ROOT, "src", "abi");

// camelCase helper: "QuipFactory" -> "quipFactoryAbi"
function toExportName(name) {
  return name.charAt(0).toLowerCase() + name.slice(1) + "Abi";
}

const CONTRACTS = [
  { name: "Deployer", path: "Deployer.sol/Deployer.json" },
  { name: "QuipFactory", path: "QuipFactory.sol/QuipFactory.json" },
  { name: "QuipWallet", path: "QuipWallet.sol/QuipWallet.json" },
];

mkdirSync(ABI_DIR, { recursive: true });

for (const contract of CONTRACTS) {
  const artifactPath = join(OUT_DIR, contract.path);
  const artifact = JSON.parse(readFileSync(artifactPath, "utf-8"));
  const abi = artifact.abi;

  const exportName = toExportName(contract.name);
  const tsContent = `export const ${exportName} = ${JSON.stringify(abi, null, 2)} as const;\n`;

  const outPath = join(ABI_DIR, `${contract.name}.ts`);
  writeFileSync(outPath, tsContent);
  console.log(`Wrote ${outPath} (${abi.length} entries)`);
}
