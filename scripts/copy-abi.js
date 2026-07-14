#!/usr/bin/env node

/**
 * Copy ABIs from Foundry output to src/abi/ and extract bytecode.
 *
 * 1. Reads Foundry artifact JSON from out/ and extracts the ABI array,
 *    writing it as a TypeScript file with `as const` for viem type inference.
 * 2. Generates a barrel re-export file at src/abi/index.ts.
 * 3. Extracts WOTSPlusImplementation bytecode, links the WOTSPlus library address,
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
  {
    name: "WOTSPlusImplementation",
    path: "WOTSPlusImplementation.sol/WOTSPlusImplementation.json",
    exportName: "wotsPlusImplementationAbi",
  },
  { name: "QuipPaymaster", path: "QuipPaymaster.sol/QuipPaymaster.json" },
];

// Shrincs ABIs live in their own directory (src/v1/shrincs/abi/) with a
// hand-maintained barrel; only the contract files are regenerated here.
const SHRINCS_ABI_DIR = join(ROOT, "src", "v1", "shrincs", "abi");
const SHRINCS_CONTRACTS = [
  { name: "ShrincsWallet", path: "ShrincsWallet.sol/ShrincsWallet.json" },
  { name: "ShrincsPaymaster", path: "ShrincsPaymaster.sol/ShrincsPaymaster.json" },
];

mkdirSync(ABI_DIR, { recursive: true });

const barrelLines = [];

for (const contract of CONTRACTS) {
  const artifactPath = join(OUT_DIR, contract.path);
  const artifact = JSON.parse(readFileSync(artifactPath, "utf-8"));
  const abi = artifact.abi;

  const exportName = contract.exportName ?? toExportName(contract.name);
  const tsContent = `export const ${exportName} = ${JSON.stringify(abi, null, 2)} as const;\n`;

  const outPath = join(ABI_DIR, `${contract.name}.ts`);
  writeFileSync(outPath, tsContent);
  console.log(`Wrote ${outPath} (${abi.length} entries)`);

  barrelLines.push(`export { ${exportName} } from "./${contract.name}.js";`);
}

for (const contract of SHRINCS_CONTRACTS) {
  const artifact = JSON.parse(readFileSync(join(OUT_DIR, contract.path), "utf-8"));
  const exportName = toExportName(contract.name);
  const header =
    `// Auto-generated from out/${contract.path} — do not edit by hand.\n` +
    `// Regenerate with \`npm run copy-abi\` after \`forge build\` when the contract interface changes.\n\n`;
  const tsContent = `${header}export const ${exportName} = ${JSON.stringify(artifact.abi, null, 2)} as const;\n`;
  const outPath = join(SHRINCS_ABI_DIR, `${contract.name}.ts`);
  writeFileSync(outPath, tsContent);
  console.log(`Wrote ${outPath} (${artifact.abi.length} entries)`);
}

// The ERC-4337 v0.7 EntryPoint is an external canonical contract, not built by
// forge, so its ABI is sourced from the committed test fixture (which also holds
// the deployedBytecode the integration tests setCode) rather than from out/.
const entryPointFixturePath = join(
  ROOT,
  "src",
  "v1",
  "tests",
  "fixtures",
  "entrypoint-v0.7.json"
);
const entryPointFixture = JSON.parse(
  readFileSync(entryPointFixturePath, "utf-8")
);
if (!Array.isArray(entryPointFixture.abi)) {
  throw new Error(
    `${entryPointFixturePath} is missing an "abi" array; cannot generate EntryPointV07.ts`
  );
}
const entryPointTs = `export const entryPointV07Abi = ${JSON.stringify(
  entryPointFixture.abi,
  null,
  2
)} as const;\n`;
const entryPointOut = join(ABI_DIR, "EntryPointV07.ts");
writeFileSync(entryPointOut, entryPointTs);
console.log(`Wrote ${entryPointOut} (${entryPointFixture.abi.length} entries)`);
barrelLines.push(`export { entryPointV07Abi } from "./EntryPointV07.js";`);

// Write barrel re-export
const barrelPath = join(ABI_DIR, "index.ts");
writeFileSync(barrelPath, barrelLines.join("\n") + "\n");
console.log(`Wrote ${barrelPath}`);

// --- Bytecode extraction ---
const addresses = JSON.parse(
  readFileSync(join(ROOT, "src", "v1", "addresses.json"), "utf-8")
);
const wotsAddress = addresses.WOTSPlus.toLowerCase().replace("0x", "");

const walletArtifact = JSON.parse(
  readFileSync(join(OUT_DIR, "WOTSPlusImplementation.sol/WOTSPlusImplementation.json"), "utf-8")
);
let bytecode = walletArtifact.bytecode.object;

// Replace library placeholder (__$<hash>$__) with actual WOTSPlus address
bytecode = bytecode.replace(/__\$[0-9a-fA-F]{34}\$__/g, wotsAddress);

const bytecodeOut = join(ROOT, "src", "v1", "bytecode.json");
writeFileSync(
  bytecodeOut,
  JSON.stringify({ wotsPlusImplementationCreationCode: bytecode }, null, 2) + "\n"
);
console.log(`Wrote ${bytecodeOut} (${bytecode.length} hex chars)`);
