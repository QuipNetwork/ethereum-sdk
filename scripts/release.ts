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
 * Address derivation is split (mirrors script/PredictAddresses.s.sol):
 *
 *   - LIVE contracts (WalletFactory, ShrincsWallet, ShrincsPaymaster)
 *     deploy straight through CreateX with SENDER-GUARDED salts — the
 *     address is f(CreateX, operator, salt preimage), identical on every
 *     chain for the same operator. The operator is PINNED as
 *     `CANONICAL_OPERATOR` below; a `DEPLOY_OPERATOR` env var that
 *     disagrees with it is rejected rather than silently honoured.
 *   - SUNSET WOTS+-era contracts (WOTSPlus, WOTSPlusImplementation,
 *     QuipPaymaster) keep their historical derivation through the
 *     deprecated `Deployer` (itself CreateX-deployed on an unguarded
 *     salt); those addresses depend only on (Deployer, salt).
 *
 * In both cases addresses are invariant across chains. The bytecode
 * snapshot exists so MIDL — which deploys the same artifact through a
 * different toolchain — can replay the exact Foundry-compiled bytes.
 *
 * Usage:
 *   forge build
 *   npm run release   # or: make release
 */

import fs from "node:fs";
import path from "node:path";
import {
  concatHex,
  encodeAbiParameters,
  getAddress,
  getContractAddress,
  getCreate2Address,
  isAddress,
  keccak256,
  padHex,
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

// CreateX singleton (https://github.com/pcaversaccio/createx) — the live
// system's only deploy dependency. Live contracts deploy through its
// sender-guarded CREATE3 path; it also (historically) bootstrapped the
// now-deprecated Quip `Deployer` via an unguarded salt.
const CREATEX_ADDRESS: Address = "0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed";

// The deploy operator. Live canonical addresses are a FUNCTION of this
// address (sender-guarded salts), so the release cannot be computed
// without it. Must match the `DEPLOY_OPERATOR` used by the Solidity
// deploy scripts.
// PINNED, mirroring `DeployConstants.CANONICAL_OPERATOR` in
// script/Constants.sol. A release computed for the wrong operator would rewrite
// `addresses.json` with a plausible-looking, entirely wrong address set.
// `DEPLOY_OPERATOR` may still be supplied (the Makefile sets it) but must AGREE.
export const CANONICAL_OPERATOR: Address = getAddress(
  "0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26",
);

const DEPLOY_OPERATOR: Address = (() => {
  const raw = process.env.DEPLOY_OPERATOR;
  if (raw === undefined || raw === "") return CANONICAL_OPERATOR;
  if (!isAddress(raw)) {
    throw new Error(`DEPLOY_OPERATOR is not a valid address: ${raw}`);
  }
  if (getAddress(raw) !== CANONICAL_OPERATOR) {
    throw new Error(
      `DEPLOY_OPERATOR (${getAddress(raw)}) disagrees with the pinned ` +
        `CANONICAL_OPERATOR (${CANONICAL_OPERATOR}). Live canonical addresses ` +
        "(WalletFactory, Shrincs*) are a function of the operator — releasing " +
        "under a different one publishes a wrong address set. Update the pin " +
        "here and in script/Constants.sol together if the operator changed.",
    );
  }
  return CANONICAL_OPERATOR;
})();

// Solady CREATE3 proxy initcode hash:
// keccak256(hex"67363d3d37363d34f03d5260086018f3").
const PROXY_INITCODE_HASH: Hex =
  "0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f";

// ── Salts ───────────────────────────────────────────────────────────────

// LIVE salt preimages — mirror script/DeployFactoryBase.sol and
// script/DeployShrincsBase.sol exactly. The Shrincs implementation salts
// bind the verifier scheme tag (`SHRINCSParams.PROFILE_ID`, the keccak of
// the profile name) so an impl built against a different cryptographic
// scheme structurally lands at a different address.
const SHRINCS_PROFILE_ID = keccak256(toHex("shrincs-256s-keccak"));

const LIVE_SALT_PREIMAGES = {
  WalletFactoryImpl: toHex("QUIP:WalletFactory:Impl:V1.0.0-beta"),
  WalletFactoryProxy: toHex("QUIP:WalletFactory:Proxy:V1.0.0-beta"),
  ShrincsWalletImplementation: concatHex([
    toHex("QUIP:ShrincsWallet:V1.1:"),
    SHRINCS_PROFILE_ID,
  ]),
  // The paymaster versions independently of the wallet — it rolled to
  // V1.0.1-beta when `initialize` began taking the full public-key bundle.
  ShrincsPaymasterImpl: concatHex([
    toHex("QUIP:ShrincsPaymaster:Impl:V1.0.1-beta:"),
    SHRINCS_PROFILE_ID,
  ]),
  ShrincsPaymasterProxy: toHex("QUIP:ShrincsPaymaster:Proxy:V1.0.1-beta"),
} as const;

// SUNSET WOTS+-era salts — mirror script/deprecated/DeployerCreate3.sol
// consumers: keccak256("QUIP:<Name>:<Version>").
//
// The Deployer keeps its v1 salt — its on-chain address is the pin point
// for the deployed WOTS+-era artifacts (Base Sepolia), and bumping it
// would invalidate every downstream prediction. The WOTS+ contracts sit
// at V1.1 and are frozen there.

const DEPLOYER_SALT_PREIMAGE = "QUIP:Deployer:V1";
const WOTS_ERA_VERSION = "V1.1";

function wotsEraSalt(name: string): Hex {
  return keccak256(toHex(`QUIP:${name}:${WOTS_ERA_VERSION}`));
}

const SALTS = {
  Deployer: keccak256(toHex(DEPLOYER_SALT_PREIMAGE)),
  WOTSPlus: wotsEraSalt("WOTSPlus"),
  WOTSPlusImplementation: wotsEraSalt("WOTSPlusImplementation"),
  QuipPaymasterImpl: keccak256(
    toHex(`QUIP:QuipPaymaster:Impl:${WOTS_ERA_VERSION}`),
  ),
  QuipPaymasterProxy: keccak256(
    toHex(`QUIP:QuipPaymaster:Proxy:${WOTS_ERA_VERSION}`),
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

// ── Sender-guarded CreateX derivation (live contracts) ──────────────────
// Mirrors script/CreateXHelpers.sol, pinned against the real CreateX
// singleton by test/script/Deploy.t.sol:
//   rawSalt     = bytes20(operator) ‖ 0x00 ‖ bytes11(keccak256(preimage))
//                 (first 20 bytes == msg.sender → permissioned salt;
//                  21st byte 0x00 → no chainid, chain-invariant)
//   guardedSalt = keccak256(bytes32(uint160(operator)) ‖ rawSalt)
//   address     = CREATE3(CreateX, guardedSalt)
// NOTE the CreateX API asymmetry: `deployCreate3` consumes the RAW salt
// (and guards internally); address prediction consumes the GUARDED salt.

function senderGuardedRawSalt(operator: Address, preimage: Hex): Hex {
  const entropy11 = keccak256(preimage).slice(2, 2 + 22);
  return `0x${operator.slice(2).toLowerCase()}00${entropy11}` as Hex;
}

function senderGuardedSalt(operator: Address, rawSalt: Hex): Hex {
  return keccak256(concatHex([padHex(operator, { size: 32 }), rawSalt]));
}

function senderGuardedAddress(operator: Address, preimage: Hex): Address {
  return computeCreate3Address(
    CREATEX_ADDRESS,
    senderGuardedSalt(operator, senderGuardedRawSalt(operator, preimage)),
  );
}

const FACTORY_IMPL_ADDRESS = senderGuardedAddress(
  DEPLOY_OPERATOR,
  LIVE_SALT_PREIMAGES.WalletFactoryImpl,
);
const FACTORY_PROXY_ADDRESS = senderGuardedAddress(
  DEPLOY_OPERATOR,
  LIVE_SALT_PREIMAGES.WalletFactoryProxy,
);
const SHRINCS_WALLET_IMPL_ADDRESS = senderGuardedAddress(
  DEPLOY_OPERATOR,
  LIVE_SALT_PREIMAGES.ShrincsWalletImplementation,
);
const SHRINCS_PAYMASTER_IMPL_ADDRESS = senderGuardedAddress(
  DEPLOY_OPERATOR,
  LIVE_SALT_PREIMAGES.ShrincsPaymasterImpl,
);
const SHRINCS_PAYMASTER_PROXY_ADDRESS = senderGuardedAddress(
  DEPLOY_OPERATOR,
  LIVE_SALT_PREIMAGES.ShrincsPaymasterProxy,
);

// ── Deployer-derived addresses (sunset WOTS+ era) ───────────────────────
// CreateX wraps an UNGUARDED user-provided salt as keccak256(abi.encode(salt))
// before passing it to its CREATE3 proxy — the fallback branch the historical
// `Deployer` bootstrap (script/deprecated/DeployDeployer.s.sol) went through.
function createxGuard(salt: Hex): Hex {
  return keccak256(encodeAbiParameters([{ type: "bytes32" }], [salt]));
}

const DEPLOYER_ADDRESS = computeCreate3Address(
  CREATEX_ADDRESS,
  createxGuard(SALTS.Deployer),
);
const WOTS_ADDRESS = computeCreate3Address(DEPLOYER_ADDRESS, SALTS.WOTSPlus);
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
  /// Sender-guarded rows only: the DEPLOY_OPERATOR the address derives from.
  operator?: Address;
  /// Sender-guarded rows only: human-readable salt preimage (the raw salt in
  /// `salt` is bytes20(operator) ‖ 0x00 ‖ bytes11(keccak256(preimage))).
  saltPreimage?: string;
  salt: Hex;
  /// Sender-guarded rows only: keccak256(bytes32(operator) ‖ rawSalt) — what
  /// CREATE3 address prediction consumes (deploys consume the raw `salt`).
  guardedSalt?: Hex;
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
  /// Set for live sender-guarded CreateX rows; WOTS+-era rows omit it and
  /// default to the historical Deployer derivation.
  senderGuarded?: { operator: Address; saltPreimage: string };
}

function writeRelease(artifact: FoundryArtifact, args: BuildArgs): void {
  const release: ReleaseFile = {
    _comment: args.comment,
    address: args.address,
    chainId: "*",
    network: "all EVM networks (CREATE3-deterministic)",
    deploymentMethod: args.senderGuarded
      ? "CREATE3 via CreateX (sender-guarded salt)"
      : "CREATE3 via Deployer (sunset WOTS+ era)",
    deployer: args.senderGuarded ? CREATEX_ADDRESS : DEPLOYER_ADDRESS,
    ...(args.senderGuarded
      ? {
          operator: args.senderGuarded.operator,
          saltPreimage: args.senderGuarded.saltPreimage,
        }
      : {}),
    salt: args.salt,
    ...(args.senderGuarded
      ? {
          guardedSalt: senderGuardedSalt(args.senderGuarded.operator, args.salt),
        }
      : {}),
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
  console.log("Live (CreateX-direct, sender-guarded):");
  console.log(`  Deploy operator:          ${DEPLOY_OPERATOR}`);
  console.log(`  WalletFactory (impl):     ${FACTORY_IMPL_ADDRESS}`);
  console.log(`  WalletFactory (proxy):    ${FACTORY_PROXY_ADDRESS}`);
  console.log(`  ShrincsWallet (impl):     ${SHRINCS_WALLET_IMPL_ADDRESS}`);
  console.log(`  ShrincsPaymaster (impl):  ${SHRINCS_PAYMASTER_IMPL_ADDRESS}`);
  console.log(`  ShrincsPaymaster (proxy): ${SHRINCS_PAYMASTER_PROXY_ADDRESS}`);
  console.log(
    "  (Shrincs handles are hand-pinned in src/v1/shrincs/addresses.ts —",
  );
  console.log("   update them there if the rows above differ.)");
  console.log("Sunset WOTS+ era (via deprecated Deployer):");
  console.log(`  Deployer:                      ${DEPLOYER_ADDRESS}`);
  console.log(`  WOTSPlus:                      ${WOTS_ADDRESS}`);
  console.log(`  WOTSPlusImplementation (impl): ${WALLET_ADDRESS}`);
  console.log(`  QuipPaymaster (impl):          ${PAYMASTER_IMPL_ADDRESS}`);
  console.log(`  QuipPaymaster (proxy):         ${PAYMASTER_PROXY_ADDRESS}`);
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

  // WalletFactory: implementation creation bytecode WITHOUT ctor args (the
  // factory no longer links WOTSPlus — it vets arbitrary wallet impls). The
  // snapshotted bytecode is the UUPS IMPLEMENTATION; the canonical user-facing
  // factory is the ERC-1967 proxy at FACTORY_PROXY_ADDRESS (recorded in
  // addresses.json). The proxy is intentionally NOT snapshotted: its creation
  // code embeds `initialize(owner)`, which varies per chain — deploy scripts
  // compose it (see script/DeployFactoryBase.sol). CREATE3 addresses are
  // invariant to constructor args either way.
  const factory = readArtifact("WalletFactory");
  writeRelease(factory, {
    contractDir: "WalletFactory.sol",
    comment:
      "WalletFactory implementation creation bytecode (no constructor args) for sender-guarded CREATE3 deployment via CreateX. Generated by scripts/release.ts from Foundry artifacts. NOTE: this is the implementation address — the canonical user-facing factory is the ERC-1967 proxy (see src/v1/addresses.json:WalletFactory).",
    address: FACTORY_IMPL_ADDRESS,
    salt: senderGuardedRawSalt(
      DEPLOY_OPERATOR,
      LIVE_SALT_PREIMAGES.WalletFactoryImpl,
    ),
    senderGuarded: {
      operator: DEPLOY_OPERATOR,
      saltPreimage: "QUIP:WalletFactory:Impl:V1.0.0-beta",
    },
    creationBytecode: ensureHex(factory.bytecode.object),
    constructorArgsDescription:
      "constructor(uint256 maxFee_). NOT encoded into this snapshot. Deploy scripts must abi.encode (uint256) the max execute-fee bound and append before calling CreateX.deployCreate3. The owner is set on the proxy via initialize(address payable).",
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
  // WalletFactory is the LIVE ERC-1967 proxy (sender-guarded CreateX row —
  // a function of DEPLOY_OPERATOR); the remaining keys are sunset WOTS+-era
  // rows kept for the deployed Base Sepolia artifacts. The wallet/paymaster
  // impl entries are surfaced so tooling can verify which impls are vetted
  // on a given chain without re-deriving from salts.
  const addresses = {
    Deployer: DEPLOYER_ADDRESS,
    WOTSPlus: WOTS_ADDRESS,
    WalletFactory: FACTORY_PROXY_ADDRESS,
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
