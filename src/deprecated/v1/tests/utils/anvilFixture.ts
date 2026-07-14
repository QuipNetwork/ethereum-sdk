// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Shared fixture utilities for integration tests. Replaces the per-file
// duplication of forge-artifact loading, bytecode linking, anvil bootstrap,
// and wallet creation.

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  type TestClient,
  type TransactionReceipt,
  type Chain,
  createPublicClient,
  createWalletClient,
  createTestClient,
  http,
  toHex,
  concat,
  parseEther,
  parseEventLogs,
} from "viem";
import { createAnvil, type Anvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { quipFactoryAbi } from "../../../../v1/abi/QuipFactory.js";
import { entryPointV07Abi } from "../../../../v1/abi/EntryPointV07.js";
import { CANONICAL_ENTRYPOINT_V07 } from "../../../../v1/addresses.js";
import { QuipSigner } from "../../signer.js";
import { createInMemoryBurnSet, type InMemoryBurnSet } from "../../burnSet.js";
import { WOTSPlusImplementationClient } from "../../walletClient.js";
import {
  encodeInit,
  type WinternitzAddress,
  MAX_KEYS,
} from "../../wotsCodec.js";

// ─── Constants ──────────────────────────────────────────────────────

/// Anvil's first prefunded dev account. Used as the default deployer for
/// every integration test.
export const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;

export const DEFAULT_ACCOUNT: PrivateKeyAccount = privateKeyToAccount(
  ANVIL_PRIV_KEY
);

/// Factory MAX_FEE used across local-anvil integration tests. The fork test
/// uses a larger value (1 ETH) and constructs its own; keep this in sync with
/// the existing local-anvil contract.
export const DEFAULT_MAX_FEE = 10n ** 16n;

/// Hand-assigned anvil ports per test file. A registry beats per-file magic
/// numbers because port collisions otherwise surface as opaque "Address
/// already in use" failures with no hint about which other file is the
/// culprit.
export const ANVIL_PORTS = {
  errors: 8547,
  reads: 8548,
  gas: 8549,
  hardening: 8551,
  erc4337Wallet: 8552,
  erc4337Paymaster: 8553,
  events: 8554,
  pqPaths: 8555,
  // 8556 reserved
  dualSig: 8557,
  erc1271: 8558,
  factoryUpgrade: 8559,
} as const;

// ─── Forge artifact loading ─────────────────────────────────────────

interface ForgeArtifact {
  bytecode: {
    object: string;
    linkReferences: Record<
      string,
      Record<string, Array<{ start: number; length: number }>>
    >;
  };
  abi: unknown;
}

function readForgeArtifact(relativePath: string): ForgeArtifact {
  return JSON.parse(
    readFileSync(join(process.cwd(), relativePath), "utf8")
  ) as ForgeArtifact;
}

export interface ForgeArtifacts {
  factoryArtifact: ForgeArtifact;
  factoryBytecode: Hex;
  walletArtifact: ForgeArtifact;
  walletUnlinkedBytecode: string;
  walletAbi: unknown;
  paymasterArtifact: ForgeArtifact;
  paymasterUnlinkedBytecode: string;
  paymasterAbi: unknown;
  wotsPlusArtifact: ForgeArtifact;
  wotsPlusBytecode: Hex;
  wotsPlusAbi: unknown;
  entryPointDeployedBytecode: Hex;
}

let cachedArtifacts: ForgeArtifacts | undefined;

/// Load all forge artifacts once per process. Subsequent calls return the
/// cached result; safe to call from every test file's module scope.
export function loadForgeArtifacts(): ForgeArtifacts {
  if (cachedArtifacts) return cachedArtifacts;

  const factoryArtifact = readForgeArtifact(
    "out/QuipFactory.sol/QuipFactory.json"
  );
  const walletArtifact = readForgeArtifact(
    "out/WOTSPlusImplementation.sol/WOTSPlusImplementation.json"
  );
  const paymasterArtifact = readForgeArtifact(
    "out/QuipPaymaster.sol/QuipPaymaster.json"
  );
  const wotsPlusArtifact = readForgeArtifact(
    "out/WOTSPlus.sol/WOTSPlus.json"
  );
  const entryPointFixture = JSON.parse(
    readFileSync(
      join(process.cwd(), "src/v1/tests/fixtures/entrypoint-v0.7.json"),
      "utf8"
    )
  ) as { deployedBytecode: Hex };

  cachedArtifacts = {
    factoryArtifact,
    factoryBytecode: factoryArtifact.bytecode.object as Hex,
    walletArtifact,
    walletUnlinkedBytecode: walletArtifact.bytecode.object,
    walletAbi: walletArtifact.abi,
    paymasterArtifact,
    paymasterUnlinkedBytecode: paymasterArtifact.bytecode.object,
    paymasterAbi: paymasterArtifact.abi,
    wotsPlusArtifact,
    wotsPlusBytecode: wotsPlusArtifact.bytecode.object as Hex,
    wotsPlusAbi: wotsPlusArtifact.abi,
    entryPointDeployedBytecode: entryPointFixture.deployedBytecode,
  };
  return cachedArtifacts;
}

// ─── Bytecode linking ───────────────────────────────────────────────

/// Substitute `__$<hash>$__` library-link placeholders in `unlinkedBytecode`
/// with the deployed `libAddress`. Works for any artifact that carries
/// `linkReferences` (wallet impl, paymaster impl, …).
export function linkBytecode(
  unlinkedBytecode: string,
  linkRefs: Record<
    string,
    Record<string, Array<{ start: number; length: number }>>
  >,
  libAddress: Address
): Hex {
  let hex = unlinkedBytecode.replace(/^0x/, "");
  const addrPlain = libAddress.replace(/^0x/, "").toLowerCase();
  for (const file of Object.values(linkRefs)) {
    for (const libRefs of Object.values(file)) {
      for (const ref of libRefs) {
        const hexStart = ref.start * 2;
        const hexLen = ref.length * 2;
        hex = hex.slice(0, hexStart) + addrPlain + hex.slice(hexStart + hexLen);
      }
    }
  }
  return ("0x" + hex) as Hex;
}

// ─── Anvil stack ────────────────────────────────────────────────────

export interface AnvilStack {
  anvil: Anvil;
  publicClient: PublicClient;
  walletClient: WalletClient;
  testClient: TestClient;
  account: PrivateKeyAccount;
  /// The factory PROXY address — the permanent factory identity.
  factoryAddress: Address;
  /// The factory UUPS implementation behind the proxy.
  factoryImplAddress: Address;
  walletImplAddress: Address;
  /// Address of the deployed WOTSPlus library — exposed for callers that
  /// need to link additional artifacts (e.g. paymaster impl).
  wotsPlusAddress: Address;
}

export interface SetupAnvilOptions {
  port: number;
  /// When true (default), set the canonical v0.7 EntryPoint bytecode at its
  /// canonical address via anvil_setCode. Hermetic, no fork needed.
  deployEntryPoint?: boolean;
  /// Override deployer account. Defaults to anvil's first prefunded account.
  account?: PrivateKeyAccount;
  /// Factory MAX_FEE constructor arg. Defaults to `DEFAULT_MAX_FEE`.
  maxFee?: bigint;
}

/// Bootstrap a hermetic anvil + Quip stack: starts anvil on `port`, places
/// the canonical EntryPoint v0.7 bytecode (optional), deploys QuipFactory,
/// deploys WOTSPlus, links + deploys the wallet impl, and vets it on the
/// factory. Returns the live clients + addresses; callers `await` it inside
/// `beforeAll` and stop with `stopAnvilStack` in `afterAll`.
export async function setupAnvilStack(
  opts: SetupAnvilOptions
): Promise<AnvilStack> {
  const account = opts.account ?? DEFAULT_ACCOUNT;
  const maxFee = opts.maxFee ?? DEFAULT_MAX_FEE;
  const deployEntryPoint = opts.deployEntryPoint ?? true;

  const artifacts = loadForgeArtifacts();
  const anvil = createAnvil({ port: opts.port });
  await anvil.start();

  const transport = http(`http://127.0.0.1:${anvil.port}`);
  const publicClient = createPublicClient({
    chain: foundry,
    transport,
  }) as PublicClient;
  const walletClient = createWalletClient({
    chain: foundry,
    transport,
    account,
  }) as WalletClient;
  const testClient = createTestClient({
    chain: foundry,
    mode: "anvil",
    transport,
  }) as TestClient;

  if (deployEntryPoint) {
    await testClient.setCode({
      address: CANONICAL_ENTRYPOINT_V07,
      bytecode: artifacts.entryPointDeployedBytecode,
    });
  }

  // 1. QuipFactory: UUPS impl + ERC-1967 proxy + initialize. The PROXY
  // address is the factory identity (wallets bake it in; CREATE3 wallet
  // addressing derives from it and survives impl upgrades).
  const { factoryAddress, factoryImplAddress } = await deployFactoryProxy(
    walletClient,
    publicClient,
    account,
    maxFee
  );

  // 2. WOTSPlus library
  const wotsHash = await walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: artifacts.wotsPlusAbi as any,
    bytecode: artifacts.wotsPlusBytecode,
    account,
    chain: foundry,
  });
  const wotsReceipt = await publicClient.waitForTransactionReceipt({
    hash: wotsHash,
  });
  const wotsPlusAddress = wotsReceipt.contractAddress!;

  // 3. Wallet impl (linked) + vet
  const walletBytecode = linkBytecode(
    artifacts.walletUnlinkedBytecode,
    artifacts.walletArtifact.bytecode.linkReferences,
    wotsPlusAddress
  );
  const implHash = await walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: artifacts.walletAbi as any,
    bytecode: walletBytecode,
    args: [factoryAddress],
    account,
    chain: foundry,
  });
  const implReceipt = await publicClient.waitForTransactionReceipt({
    hash: implHash,
  });
  const walletImplAddress = implReceipt.contractAddress!;

  const vetHash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "vetImplementation",
    args: [walletImplAddress],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: vetHash });

  return {
    anvil,
    publicClient,
    walletClient,
    testClient,
    account,
    factoryAddress,
    factoryImplAddress,
    walletImplAddress,
    wotsPlusAddress,
  };
}

export async function stopAnvilStack(stack: AnvilStack): Promise<void> {
  await stack.anvil.stop().catch(() => {});
}

// ─── Fresh wallet ───────────────────────────────────────────────────

export interface FreshWallet {
  signer: QuipSigner;
  vaultId: Hex;
  client: WOTSPlusImplementationClient;
  walletAddress: Address;
  disasterKey: WinternitzAddress;
  ownershipKey: WinternitzAddress;
  transactionKeys: WinternitzAddress[];
  recoveryKeys: WinternitzAddress[];
  verificationKeys: WinternitzAddress[];
  initPayload: Hex;
  creationReceipt: TransactionReceipt;
  burnSet: InMemoryBurnSet;
  isBurned: (seed: Hex) => boolean;
  markBurned: (seed: Hex) => void;
}

export interface CreateFreshWalletOptions {
  /// Anvil-funded balance dropped on the wallet via `anvil_setBalance`.
  /// Defaults to 10 ETH. Set 0n to skip.
  walletBalance?: bigint;
  /// ETH pre-deposited at the canonical EntryPoint on behalf of the wallet,
  /// via `EntryPoint.depositTo(wallet)`. Required for ERC-4337 paths that
  /// pay prefund from the deposit. Defaults to 0n; set explicitly for 4337
  /// tests.
  entryPointDeposit?: bigint;
  /// Account that pays gas for the factory deploy. Defaults to the stack's
  /// own deployer account.
  deployerAccount?: PrivateKeyAccount;
  /// Owner address recorded on the wallet (the `to` arg of
  /// `deployLatestWalletProxy`). Defaults to the stack's deployer.
  owner?: Address;
}

/// Deploy a fresh wallet through the factory and return a rich object: the
/// SDK client, all key material the SDK generated for the init payload, a
/// burn-set tracker (so tests can ask `isBurned(seed)` without consuming as
/// a side effect), and the creation receipt.
///
/// `seedByte` parameterizes the `quantumSecret` and `vaultId` (both filled
/// with the byte) so each test can get an isolated wallet whose key material
/// doesn't collide with other tests' wallets.
export async function createFreshWallet(
  stack: AnvilStack,
  seedByte: number,
  opts: CreateFreshWalletOptions = {}
): Promise<FreshWallet> {
  const walletBalance = opts.walletBalance ?? parseEther("10");
  const entryPointDeposit = opts.entryPointDeposit ?? 0n;
  const deployer = opts.deployerAccount ?? stack.account;
  const owner = opts.owner ?? deployer.address;

  const quantumSecret = new Uint8Array(32).fill(seedByte);
  const burnSet = createInMemoryBurnSet();
  const burned = new Set<Hex>();
  const consume = (seed: Hex): void => {
    burnSet.consume(seed);
    burned.add(seed);
  };
  const signer = new QuipSigner(quantumSecret, consume);
  const vaultId = toHex(new Uint8Array(32).fill(seedByte));

  const disasterKey = signer.generateKeyPair(vaultId).publicKey;
  const ownershipKey = signer.generateKeyPair(vaultId).publicKey;
  const transactionKeys = Array.from({ length: MAX_KEYS }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  const recoveryKeys = Array.from({ length: MAX_KEYS }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  const verificationKeys = Array.from({ length: MAX_KEYS }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  const initPayload = encodeInit(
    disasterKey,
    ownershipKey,
    transactionKeys,
    recoveryKeys,
    verificationKeys
  );

  const hash = await stack.walletClient.writeContract({
    chain: foundry,
    address: stack.factoryAddress,
    abi: quipFactoryAbi,
    functionName: "deployLatestWalletProxy",
    args: [vaultId, owner, initPayload],
    account: deployer,
  });
  const creationReceipt = await stack.publicClient.waitForTransactionReceipt({
    hash,
  });
  const logs = parseEventLogs({
    abi: quipFactoryAbi,
    logs: creationReceipt.logs,
    eventName: "QuipCreated",
  });
  const walletAddress = logs[0].args.quip;

  if (walletBalance > 0n) {
    await stack.testClient.setBalance({
      address: walletAddress,
      value: walletBalance,
    });
  }
  if (entryPointDeposit > 0n) {
    await stack.walletClient.writeContract({
      chain: foundry,
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "depositTo",
      args: [walletAddress],
      value: entryPointDeposit,
      account: deployer,
    });
  }

  const client = new WOTSPlusImplementationClient(
    signer,
    vaultId,
    walletAddress,
    stack.publicClient,
    stack.walletClient,
    deployer.address,
    foundry.id
  );

  return {
    signer,
    vaultId,
    client,
    walletAddress,
    disasterKey,
    ownershipKey,
    transactionKeys,
    recoveryKeys,
    verificationKeys,
    initPayload,
    creationReceipt,
    burnSet,
    isBurned: (seed: Hex) => burned.has(seed),
    markBurned: (seed: Hex) => consume(seed),
  };
}

// ─── ERC-1967 proxy helpers ─────────────────────────────────────────

/// Deploy the QuipFactory as UUPS impl + ERC-1967 proxy and initialize the
/// proxy with `owner` (defaults to the deployer). Returns the PROXY address
/// (the permanent factory identity) alongside the impl behind it.
export async function deployFactoryProxy(
  walletClient: WalletClient,
  publicClient: PublicClient,
  account: PrivateKeyAccount,
  maxFee: bigint,
  owner?: Address,
  chain: Chain = foundry
): Promise<{ factoryAddress: Address; factoryImplAddress: Address }> {
  const { factoryBytecode } = loadForgeArtifacts();
  const implHash = await walletClient.deployContract({
    abi: quipFactoryAbi,
    bytecode: factoryBytecode,
    args: [maxFee],
    account,
    chain,
  });
  const implReceipt = await publicClient.waitForTransactionReceipt({
    hash: implHash,
  });
  const factoryImplAddress = implReceipt.contractAddress!;
  const factoryAddress = await deployErc1967Proxy(
    walletClient,
    publicClient,
    account,
    factoryImplAddress,
    chain
  );
  const initHash = await walletClient.writeContract({
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "initialize",
    args: [owner ?? account.address],
    account,
    chain,
  });
  await publicClient.waitForTransactionReceipt({ hash: initHash });
  return { factoryAddress, factoryImplAddress };
}

import { deployErc1967Proxy } from "../../../../v1/tests/utils/deployErc1967Proxy.js";

// `deployErc1967Proxy` is family-agnostic and shared with the SHRINCS
// fixture — it lives in its own live module; re-exported here so existing
// importers of this fixture keep working.
export { deployErc1967Proxy } from "../../../../v1/tests/utils/deployErc1967Proxy.js";
