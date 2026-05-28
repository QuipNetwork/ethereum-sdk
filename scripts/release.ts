// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Release Script (Foundry-native)
 *
 * Reads Foundry build artifacts from `out/` (compiled per `foundry.toml`),
 * computes the canonical CREATE3 addresses for the Quip contracts, and
 * writes:
 *
 *   - `deployments/bytecode/<Contract>.sol/<address>.json`  — per-release
 *     bytecode snapshot with compiler settings copied verbatim from the
 *     Foundry artifact metadata.
 *   - `deployments/bytecode/<Contract>.sol/latest.json`     — pointer to
 *     the current release file.
 *   - `src/v1/addresses.json`                               — SDK-facing
 *     address registry.
 *
 * The MIDL deploy scripts (`deploy/midl_regtest/*.cts`) consume the
 * release bytecode + salt via `lib/deploy.cts::loadReleaseBytecode` to
 * deploy the same compiled bytecode against the MIDL Hardhat toolchain.
 *
 * CREATE3 addresses depend only on (Deployer, salt); they're invariant
 * across chains. The bytecode snapshot exists so MIDL — which deploys
 * the same artifact through a different toolchain — can replay the
 * exact Foundry-compiled bytes.
 *
 * Usage:
 *   forge build
 *   npm run release   # or: make release
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  encodeAbiParameters,
  getContractAddress,
  getCreate2Address,
  keccak256,
  parseEther,
  toHex,
  type Address,
  type Hex,
} from "viem";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");
const OUT_DIR = path.join(ROOT, "out");
const BYTECODE_DIR = path.join(ROOT, "deployments/bytecode");
const ADDRESSES_FILE = path.join(ROOT, "src/v1/addresses.json");

// CreateX deployer (https://github.com/pcaversaccio/createx). Bootstraps
// the canonical Quip `Deployer` via its salt-guarded CREATE3 path.
const CREATEX_ADDRESS: Address = "0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed";

// Solady CREATE3 proxy initcode hash:
// keccak256(hex"67363d3d37363d34f03d5260086018f3").
const PROXY_INITCODE_HASH: Hex =
  "0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f";

// ── Salts ───────────────────────────────────────────────────────────────
// Mirror the Solidity deploy scripts (script/Deploy*.s.sol) exactly:
//   keccak256("QUIP:<Name>:V1").

function quipSalt(name: string): Hex {
  return keccak256(toHex(`QUIP:${name}:V1`));
}

const SALTS = {
  Deployer: quipSalt("Deployer"),
  WOTSPlus: quipSalt("WOTSPlus"),
  QuipFactory: quipSalt("QuipFactory"),
  QuipWallet: quipSalt("QuipWallet"),
  QuipPaymasterImpl: keccak256(toHex("QUIP:QuipPaymaster:Impl:V1")),
  QuipPaymasterProxy: keccak256(toHex("QUIP:QuipPaymaster:Proxy:V1")),
} as const;

// ── CREATE3 derivation ──────────────────────────────────────────────────

function computeCreate3Address(deployer: Address, salt: Hex): Address {
  const proxy = getCreate2Address({
    from: deployer,
    salt,
    bytecodeHash: PROXY_INITCODE_HASH,
  });
  return getContractAddress({ from: proxy, nonce: 1n });
}

// CreateX wraps the user-provided salt as keccak256(abi.encode(salt))
// before passing it to its CREATE3 proxy. Matches the on-chain behaviour
// of the canonical CreateX deployment used by `DeployDeployer.s.sol`.
function createxGuard(salt: Hex): Hex {
  return keccak256(encodeAbiParameters([{ type: "bytes32" }], [salt]));
}

const DEPLOYER_ADDRESS = computeCreate3Address(
  CREATEX_ADDRESS,
  createxGuard(SALTS.Deployer),
);
const WOTS_ADDRESS = computeCreate3Address(DEPLOYER_ADDRESS, SALTS.WOTSPlus);
const FACTORY_ADDRESS = computeCreate3Address(
  DEPLOYER_ADDRESS,
  SALTS.QuipFactory,
);
const WALLET_ADDRESS = computeCreate3Address(
  DEPLOYER_ADDRESS,
  SALTS.QuipWallet,
);
const PAYMASTER_PROXY_ADDRESS = computeCreate3Address(
  DEPLOYER_ADDRESS,
  SALTS.QuipPaymasterProxy,
);

// ── Foundry artifact reader ─────────────────────────────────────────────

interface FoundryArtifact {
  abi: unknown[];
  bytecode: { object: string; linkReferences: Record<string, unknown> };
  deployedBytecode: { object: string };
  metadata: {
    compiler: { version: string };
    settings: {
      evmVersion: string;
      optimizer: { enabled: boolean; runs: number };
      metadata: { bytecodeHash: string };
    };
  };
}

function readArtifact(name: string): FoundryArtifact {
  const file = path.join(OUT_DIR, `${name}.sol/${name}.json`);
  if (!fs.existsSync(file)) {
    throw new Error(
      `Foundry artifact not found: ${file}\nRun \`forge build\` first.`,
    );
  }
  return JSON.parse(fs.readFileSync(file, "utf-8")) as FoundryArtifact;
}

// Replace solc's library placeholder (`__$<34-hex-char-hash>$__`) with
// the runtime WOTSPlus library address. This is the same substitution
// `scripts/copy-abi.js` does for the SDK's wallet creation code.
function linkWotsPlus(bytecode: string, wots: Address): Hex {
  const linked = bytecode.replace(
    /__\$[0-9a-fA-F]{34}\$__/g,
    wots.slice(2).toLowerCase(),
  );
  if (linked.includes("__$")) {
    throw new Error("Unresolved library placeholder remains after linking");
  }
  return ensureHex(linked);
}

function ensureHex(s: string): Hex {
  return (s.startsWith("0x") ? s : `0x${s}`) as Hex;
}

// ── Release writer ──────────────────────────────────────────────────────

interface ReleaseFile {
  _comment: string;
  address: Address;
  chainId: "*";
  network: string;
  deploymentMethod: string;
  deployer: Address;
  salt: Hex;
  compiler: {
    version: string;
    evmVersion: string;
    optimizer: { enabled: boolean; runs: number };
    metadata: { bytecodeHash: string };
  };
  linkedLibraries?: Record<string, Address>;
  constructorArgsDescription?: string;
  creationBytecode: Hex;
  deployedBytecode: Hex;
}

interface BuildArgs {
  contractDir: string;
  comment: string;
  address: Address;
  salt: Hex;
  creationBytecode: Hex;
  linkedLibraries?: Record<string, Address>;
  constructorArgsDescription?: string;
}

function writeRelease(artifact: FoundryArtifact, args: BuildArgs): void {
  const release: ReleaseFile = {
    _comment: args.comment,
    address: args.address,
    chainId: "*",
    network: "all EVM networks (CREATE3-deterministic)",
    deploymentMethod: "CREATE3 via Deployer",
    deployer: DEPLOYER_ADDRESS,
    salt: args.salt,
    compiler: {
      version: artifact.metadata.compiler.version,
      evmVersion: artifact.metadata.settings.evmVersion,
      optimizer: artifact.metadata.settings.optimizer,
      metadata: {
        bytecodeHash: artifact.metadata.settings.metadata.bytecodeHash,
      },
    },
    ...(args.linkedLibraries ? { linkedLibraries: args.linkedLibraries } : {}),
    ...(args.constructorArgsDescription
      ? { constructorArgsDescription: args.constructorArgsDescription }
      : {}),
    creationBytecode: args.creationBytecode,
    deployedBytecode: ensureHex(artifact.deployedBytecode.object),
  };

  const dir = path.join(BYTECODE_DIR, args.contractDir);
  fs.mkdirSync(dir, { recursive: true });

  const releaseFile = path.join(dir, `${args.address}.json`);
  fs.writeFileSync(releaseFile, JSON.stringify(release, null, 2) + "\n");
  console.log(`Wrote ${path.relative(ROOT, releaseFile)}`);

  const latestFile = path.join(dir, "latest.json");
  const latest = {
    _comment: `Reference to the current ${args.contractDir.replace(".sol", "")} release`,
    address: args.address,
    file: `${args.address}.json`,
  };
  fs.writeFileSync(latestFile, JSON.stringify(latest, null, 2) + "\n");
  console.log(`Wrote ${path.relative(ROOT, latestFile)}`);
}

// ── Main ────────────────────────────────────────────────────────────────

function main(): void {
  console.log("=".repeat(60));
  console.log("Quip Network Release (Foundry-native)");
  console.log("=".repeat(60));
  console.log(`Deployer:              ${DEPLOYER_ADDRESS}`);
  console.log(`WOTSPlus:              ${WOTS_ADDRESS}`);
  console.log(`QuipFactory:           ${FACTORY_ADDRESS}`);
  console.log(`QuipWallet (impl):     ${WALLET_ADDRESS}`);
  console.log(`QuipPaymaster (proxy): ${PAYMASTER_PROXY_ADDRESS}`);
  console.log("");

  // WOTSPlus: no constructor, no library deps.
  const wots = readArtifact("WOTSPlus");
  writeRelease(wots, {
    contractDir: "WOTSPlus.sol",
    comment:
      "WOTSPlus library bytecode for CREATE3 deployment. Generated by scripts/release.ts from Foundry artifacts.",
    address: WOTS_ADDRESS,
    salt: SALTS.WOTSPlus,
    creationBytecode: ensureHex(wots.bytecode.object),
  });

  // QuipFactory: constructor (address payable initialOwner, uint256 maxFee_).
  // Placeholder constructor args — CREATE3 address is independent of bytecode
  // so per-chain owner/fee variations don't shift the address.
  const factory = readArtifact("QuipFactory");
  const placeholderOwner: Address = "0x0000000000000000000000000000000000000000";
  const placeholderMaxFee = parseEther("0.1");
  const factoryCtorArgs = encodeAbiParameters(
    [{ type: "address" }, { type: "uint256" }],
    [placeholderOwner, placeholderMaxFee],
  );
  writeRelease(factory, {
    contractDir: "QuipFactory.sol",
    comment:
      "QuipFactory bytecode for CREATE3 deployment. Generated by scripts/release.ts from Foundry artifacts.",
    address: FACTORY_ADDRESS,
    salt: SALTS.QuipFactory,
    creationBytecode: ensureHex(
      linkWotsPlus(factory.bytecode.object, WOTS_ADDRESS) +
        factoryCtorArgs.slice(2),
    ),
    linkedLibraries: { WOTSPlus: WOTS_ADDRESS },
    constructorArgsDescription:
      "constructor(address payable initialOwner, uint256 maxFee_) — encoded with placeholder owner 0x0 and maxFee 0.1 ether. Address is CREATE3-deterministic and does not depend on these.",
  });

  // QuipWallet: constructor (address payable factory_).
  const wallet = readArtifact("QuipWallet");
  const walletCtorArgs = encodeAbiParameters(
    [{ type: "address" }],
    [FACTORY_ADDRESS],
  );
  writeRelease(wallet, {
    contractDir: "QuipWallet.sol",
    comment:
      "QuipWallet implementation bytecode for CREATE3 deployment. Generated by scripts/release.ts from Foundry artifacts.",
    address: WALLET_ADDRESS,
    salt: SALTS.QuipWallet,
    creationBytecode: ensureHex(
      linkWotsPlus(wallet.bytecode.object, WOTS_ADDRESS) +
        walletCtorArgs.slice(2),
    ),
    linkedLibraries: { WOTSPlus: WOTS_ADDRESS },
    constructorArgsDescription:
      "constructor(address payable factory_) — factory is the QuipFactory CREATE3 address.",
  });

  // src/v1/addresses.json — canonical EVM CREATE3 addresses. MIDL keeps its
  // own per-chain entry in src/v1/addresses.ts (NETWORK_ADDRESSES[777]).
  const addresses = {
    Deployer: DEPLOYER_ADDRESS,
    WOTSPlus: WOTS_ADDRESS,
    QuipFactory: FACTORY_ADDRESS,
    QuipPaymaster: PAYMASTER_PROXY_ADDRESS,
  };
  fs.writeFileSync(ADDRESSES_FILE, JSON.stringify(addresses, null, 2) + "\n");
  console.log(`Wrote ${path.relative(ROOT, ADDRESSES_FILE)}`);

  console.log("");
  console.log("=".repeat(60));
  console.log("Release Complete");
  console.log("=".repeat(60));
  console.log(`Compiler:  ${factory.metadata.compiler.version}`);
  console.log(`EVM:       ${factory.metadata.settings.evmVersion}`);
  console.log(
    `Optimizer: ${factory.metadata.settings.optimizer.enabled ? "enabled" : "disabled"} (${factory.metadata.settings.optimizer.runs} runs)`,
  );
}

main();
