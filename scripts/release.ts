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
import {
  encodeAbiParameters,
  getContractAddress,
  getCreate2Address,
  keccak256,
  toHex,
  type Address,
  type Hex,
} from "viem";

// Anchor every path on the project root. `npm run release` and `make
// release` both invoke this script from the package root, so `cwd()`
// is reliable here and lets the script type-check under the repo's
// root `tsconfig.json` (CJS, no `import.meta`).
const ROOT = process.cwd();
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
//   keccak256("QUIP:<Name>:<Version>").
//
// The Deployer keeps its v1 salt — its on-chain address is the cross-chain
// pin point, and bumping it would invalidate every downstream prediction
// without a corresponding redeploy via CreateX everywhere. All other
// contracts roll forward to V1.1 in lockstep with the deploy scripts.

const DEPLOYER_SALT_PREIMAGE = "QUIP:Deployer:V1";
const DOWNSTREAM_VERSION = "V1.1";

function downstreamSalt(name: string): Hex {
  return keccak256(toHex(`QUIP:${name}:${DOWNSTREAM_VERSION}`));
}

const SALTS = {
  Deployer: keccak256(toHex(DEPLOYER_SALT_PREIMAGE)),
  WOTSPlus: downstreamSalt("WOTSPlus"),
  WalletFactory: downstreamSalt("WalletFactory"),
  WOTSPlusImplementation: downstreamSalt("WOTSPlusImplementation"),
  QuipPaymasterImpl: keccak256(
    toHex(`QUIP:QuipPaymaster:Impl:${DOWNSTREAM_VERSION}`),
  ),
  QuipPaymasterProxy: keccak256(
    toHex(`QUIP:QuipPaymaster:Proxy:${DOWNSTREAM_VERSION}`),
  ),
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
  SALTS.WalletFactory,
);
const WALLET_ADDRESS = computeCreate3Address(
  DEPLOYER_ADDRESS,
  SALTS.WOTSPlusImplementation,
);
const PAYMASTER_IMPL_ADDRESS = computeCreate3Address(
  DEPLOYER_ADDRESS,
  SALTS.QuipPaymasterImpl,
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
  console.log(`WalletFactory:           ${FACTORY_ADDRESS}`);
  console.log(`WOTSPlusImplementation (impl):     ${WALLET_ADDRESS}`);
  console.log(`QuipPaymaster (impl):  ${PAYMASTER_IMPL_ADDRESS}`);
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

  // WalletFactory: WOTSPlus-linked creation bytecode WITHOUT ctor args. The
  // constructor `(address payable initialOwner, uint256 maxFee_)` is
  // chain-specific (each chain picks its own factory owner + creation fee),
  // so the deploy script must abi-encode and append these at deploy time.
  // Same pattern as the QuipPaymaster proxy below — see DeployAll.s.sol's
  // EVM-side encoding and deploy/midl_regtest/02_deploy_factory.cts for the
  // MIDL-side encoding.
  const factory = readArtifact("WalletFactory");
  writeRelease(factory, {
    contractDir: "WalletFactory.sol",
    comment:
      "WalletFactory linked creation bytecode (no constructor args) for CREATE3 deployment. Generated by scripts/release.ts from Foundry artifacts.",
    address: FACTORY_ADDRESS,
    salt: SALTS.WalletFactory,
    creationBytecode: ensureHex(
      linkWotsPlus(factory.bytecode.object, WOTS_ADDRESS),
    ),
    linkedLibraries: { WOTSPlus: WOTS_ADDRESS },
    constructorArgsDescription:
      "constructor(address payable initialOwner, uint256 maxFee_). NOT encoded into this snapshot. Deploy scripts must abi.encode (address, uint256) the per-chain values and append before calling Deployer.deploy. CREATE3 address is invariant to these args.",
  });

  // WOTSPlusImplementation: WOTSPlus-linked creation bytecode WITHOUT ctor args. The
  // constructor `(address payable factory_)` is technically canonical
  // (WalletFactory's CREATE3 address is invariant across chains) but we keep
  // the same "release = linked code only, deploy composes args" contract as
  // WalletFactory to avoid having a hidden divergence in which contracts have
  // baked-in args and which don't.
  const wallet = readArtifact("WOTSPlusImplementation");
  writeRelease(wallet, {
    contractDir: "WOTSPlusImplementation.sol",
    comment:
      "WOTSPlusImplementation linked creation bytecode (no constructor args) for CREATE3 deployment. Generated by scripts/release.ts from Foundry artifacts.",
    address: WALLET_ADDRESS,
    salt: SALTS.WOTSPlusImplementation,
    creationBytecode: ensureHex(
      linkWotsPlus(wallet.bytecode.object, WOTS_ADDRESS),
    ),
    linkedLibraries: { WOTSPlus: WOTS_ADDRESS },
    constructorArgsDescription:
      "constructor(address payable factory_). NOT encoded into this snapshot. Deploy scripts must abi.encode (address) the canonical WalletFactory CREATE3 address and append.",
  });

  // QuipPaymaster (impl): empty constructor, one WOTSPlus link. The
  // canonical paymaster address is the *proxy* (recorded in addresses.json);
  // the impl bytecode is snapshotted so MIDL — which deploys through its own
  // Hardhat toolchain — can deploy the exact Foundry-compiled bytes via
  // `lib/deploy.cts::loadReleaseBytecode`. The proxy is intentionally NOT
  // snapshotted: its creation code embeds `initialize(owner)`, which varies
  // per chain. MIDL's proxy deploy script must compose its own creation code
  // with a chain-specific owner — see `script/DeployPaymaster.s.sol` for the
  // EVM-side pattern.
  const paymaster = readArtifact("QuipPaymaster");
  writeRelease(paymaster, {
    contractDir: "QuipPaymaster.sol",
    comment:
      "QuipPaymaster implementation bytecode for CREATE3 deployment. Generated by scripts/release.ts from Foundry artifacts. NOTE: this is the implementation address — the canonical user-facing paymaster is the ERC1967 proxy at a different CREATE3 address (see src/v1/addresses.json:QuipPaymaster).",
    address: PAYMASTER_IMPL_ADDRESS,
    salt: SALTS.QuipPaymasterImpl,
    creationBytecode: ensureHex(
      linkWotsPlus(paymaster.bytecode.object, WOTS_ADDRESS),
    ),
    linkedLibraries: { WOTSPlus: WOTS_ADDRESS },
    constructorArgsDescription:
      "constructor() — no args. Constructor calls _disableInitializers() so the impl itself is inert; owner is set on the proxy via initialize().",
  });

  // src/v1/addresses.json — canonical EVM CREATE3 addresses. MIDL keeps its
  // own per-chain entry in src/v1/addresses.ts (NETWORK_ADDRESSES[777]).
  //
  // Shape must match `NetworkAddresses` in src/v1/addresses.ts (the SDK
  // reads this JSON at module load and asserts every field as `Address`).
  // The wallet/paymaster impl entries are surfaced so tooling can verify
  // which impls are vetted on a given chain without re-deriving from salts.
  const addresses = {
    Deployer: DEPLOYER_ADDRESS,
    WOTSPlus: WOTS_ADDRESS,
    WalletFactory: FACTORY_ADDRESS,
    WOTSPlusImplementation: WALLET_ADDRESS,
    QuipPaymaster: PAYMASTER_PROXY_ADDRESS,
    QuipPaymasterImpl: PAYMASTER_IMPL_ADDRESS,
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
