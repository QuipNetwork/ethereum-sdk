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

// Shrincs analog of `src/v1/tests/utils/anvilFixture.ts`: a hermetic anvil
// stack that mirrors what an FE consumer of the Shrincs TS SDK deploys —
// WalletFactory, a vetted ShrincsWallet implementation, and a ShrincsPaymaster
// (UUPS impl + ERC-1967 proxy). Returns live clients + addresses so smoke
// tests can drive the SDK against real on-chain contracts.

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  type TestClient,
  createPublicClient,
  createWalletClient,
  createTestClient,
  http,
  parseEther,
} from "viem";
import { createAnvil, type Anvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { walletFactoryAbi } from "../../../abi/WalletFactory.js";
import { entryPointV07Abi } from "../../../abi/EntryPointV07.js";
import { CANONICAL_ENTRYPOINT_V07 } from "../../../addresses.js";
import { deployErc1967Proxy } from "../../../tests/utils/deployErc1967Proxy.js";
import { shrincsPaymasterAbi } from "../../abi/ShrincsPaymaster.js";
import { HASH_SUITE_KECCAK_256 } from "../../constants.js";
import { publicKeyToAbi } from "../../shrincsCodec.js";
import { type ShrincsPublicKey } from "../../types.js";
import { ShrincsFactoryClient } from "../../shrincsFactoryClient.js";
import { ShrincsSigner } from "../../shrincsSigner.js";
import { type ShrincsWalletClient } from "../../shrincsWalletClient.js";

// ─── Constants ──────────────────────────────────────────────────────

/// Anvil's first prefunded dev account — default deployer/owner.
export const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as const;

export const DEFAULT_ACCOUNT: PrivateKeyAccount =
  privateKeyToAccount(ANVIL_PRIV_KEY);

/// Factory MAX_FEE; the Shrincs creation/execute fee defaults to 0 unless the
/// factory is configured otherwise, so this is only the construction ceiling.
export const DEFAULT_MAX_FEE = 10n ** 16n;

/// New port range, distinct from the v1 fixture's `ANVIL_PORTS` (8547-8558).
export const SHRINCS_ANVIL_PORTS = {
  smoke: 8560,
} as const;

/// The SPHINCSPlusC verifier address compile-time pinned inside
/// `SHRINCS256sKeccak` (dep `DEPLOYMENTS.md`, CREATE3 — same on every chain).
/// The fixture places its runtime bytecode here; stateless verification
/// reverts on empty code at this address.
export const SPHINCS_PLUS_C_SIBLING =
  "0xf1Bd3aE9d3907bA59FB22A77eAcCbd278b51f88A" as const;

// ─── Forge artifact loading ─────────────────────────────────────────

interface ForgeArtifact {
  bytecode: { object: string };
  deployedBytecode: { object: string };
  abi: unknown;
}

function readForgeArtifact(relativePath: string): ForgeArtifact {
  return JSON.parse(
    readFileSync(join(process.cwd(), relativePath), "utf8")
  ) as ForgeArtifact;
}

// ─── Anvil stack ────────────────────────────────────────────────────

export interface ShrincsAnvilStack {
  anvil: Anvil;
  publicClient: PublicClient;
  walletClient: WalletClient;
  testClient: TestClient;
  account: PrivateKeyAccount;
  factoryAddress: Address;
  shrincsWalletImpl: Address;
  paymasterProxy: Address;
  /// The deployed external SHRINCS verifier every wallet/paymaster signature
  /// check is delegated to (pinned as an implementation immutable).
  shrincsVerifier: Address;
}

export interface SetupShrincsAnvilOptions {
  port: number;
  account?: PrivateKeyAccount;
  maxFee?: bigint;
}

/// Boot a hermetic anvil + Shrincs stack: start anvil, place the canonical
/// EntryPoint v0.7 bytecode, deploy WalletFactory, deploy + vet a ShrincsWallet
/// implementation, and deploy a ShrincsPaymaster (impl + ERC-1967 proxy). The
/// proxy is left UNinitialized — the smoke test exercises `initialize` itself.
export async function setupShrincsAnvilStack(
  opts: SetupShrincsAnvilOptions
): Promise<ShrincsAnvilStack> {
  const account = opts.account ?? DEFAULT_ACCOUNT;
  const maxFee = opts.maxFee ?? DEFAULT_MAX_FEE;

  const factoryArtifact = readForgeArtifact(
    "out/WalletFactory.sol/WalletFactory.json"
  );
  const walletArtifact = readForgeArtifact(
    "out/ShrincsWallet.sol/ShrincsWallet.json"
  );
  const paymasterArtifact = readForgeArtifact(
    "out/ShrincsPaymaster.sol/ShrincsPaymaster.json"
  );
  const shrincsVerifierArtifact = readForgeArtifact(
    "out/SHRINCS256sKeccak.sol/SHRINCS256sKeccak.json"
  );
  const sphincsSiblingArtifact = readForgeArtifact(
    "out/SPHINCSPlusC256sKeccak.sol/SPHINCSPlusC256sKeccak.json"
  );
  const entryPointFixture = JSON.parse(
    readFileSync(
      join(process.cwd(), "src/v1/tests/fixtures/entrypoint-v0.7.json"),
      "utf8"
    )
  ) as { deployedBytecode: Hex };

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

  // Canonical EntryPoint v0.7 bytecode at its canonical address.
  await testClient.setCode({
    address: CANONICAL_ENTRYPOINT_V07,
    bytecode: entryPointFixture.deployedBytecode,
  });

  // SPHINCSPlusC sibling runtime code at its compile-time-pinned address
  // (constructor-free + storage-free, so placing runtime code is exact),
  // then the SHRINCS verifier that delegates its stateless half to it.
  await testClient.setCode({
    address: SPHINCS_PLUS_C_SIBLING,
    bytecode: sphincsSiblingArtifact.deployedBytecode.object as Hex,
  });
  const verifierHash = await walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: shrincsVerifierArtifact.abi as any,
    bytecode: shrincsVerifierArtifact.bytecode.object as Hex,
    account,
    chain: foundry,
  });
  const verifierReceipt = await publicClient.waitForTransactionReceipt({
    hash: verifierHash,
  });
  const shrincsVerifier = verifierReceipt.contractAddress!;

  // 1. WalletFactory: UUPS impl + ERC-1967 proxy + initialize. The PROXY
  // address is the factory identity wallets bake in.
  const factoryImplHash = await walletClient.deployContract({
    abi: walletFactoryAbi,
    bytecode: factoryArtifact.bytecode.object as Hex,
    args: [maxFee],
    account,
    chain: foundry,
  });
  const factoryImplReceipt = await publicClient.waitForTransactionReceipt({
    hash: factoryImplHash,
  });
  const factoryAddress = await deployErc1967Proxy(
    walletClient,
    publicClient,
    account,
    factoryImplReceipt.contractAddress!
  );
  const factoryInitHash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: walletFactoryAbi,
    functionName: "initialize",
    args: [account.address],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: factoryInitHash });

  // 2. ShrincsWallet impl (no library linking — empty linkReferences) + vet.
  const implHash = await walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: walletArtifact.abi as any,
    bytecode: walletArtifact.bytecode.object as Hex,
    args: [factoryAddress, shrincsVerifier],
    account,
    chain: foundry,
  });
  const implReceipt = await publicClient.waitForTransactionReceipt({
    hash: implHash,
  });
  const shrincsWalletImpl = implReceipt.contractAddress!;

  const vetHash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: walletFactoryAbi,
    functionName: "vetImplementation",
    args: [shrincsWalletImpl],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: vetHash });

  // 3. ShrincsPaymaster impl (same pinned-verifier ctor arg) + ERC-1967 proxy.
  const pmImplHash = await walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: paymasterArtifact.abi as any,
    bytecode: paymasterArtifact.bytecode.object as Hex,
    args: [shrincsVerifier],
    account,
    chain: foundry,
  });
  const pmImplReceipt = await publicClient.waitForTransactionReceipt({
    hash: pmImplHash,
  });
  const paymasterProxy = await deployErc1967Proxy(
    walletClient,
    publicClient,
    account,
    pmImplReceipt.contractAddress!
  );

  return {
    anvil,
    publicClient,
    walletClient,
    testClient,
    account,
    factoryAddress,
    shrincsWalletImpl,
    paymasterProxy,
    shrincsVerifier,
  };
}

export async function stopShrincsAnvilStack(
  stack: ShrincsAnvilStack
): Promise<void> {
  await stack.anvil.stop().catch(() => {});
}

// ─── Signer + factory client helpers ────────────────────────────────

/// Construct a `ShrincsSigner` from a 32-byte quantum secret filled with
/// `seedByte` (the FE master-secret analog).
export async function makeShrincsSigner(
  seedByte: number
): Promise<ShrincsSigner> {
  return ShrincsSigner.create(new Uint8Array(32).fill(seedByte));
}

/// A `ShrincsFactoryClient` bound to the stack's deployed factory + impl.
export function makeShrincsFactoryClient(
  stack: ShrincsAnvilStack
): ShrincsFactoryClient {
  return new ShrincsFactoryClient({
    publicClient: stack.publicClient,
    walletClient: stack.walletClient,
    account: stack.account.address,
    chainId: foundry.id,
    factoryAddress: stack.factoryAddress,
    walletImplementation: stack.shrincsWalletImpl,
  });
}

// ─── Fresh wallet ───────────────────────────────────────────────────

export interface FreshShrincsWallet {
  signer: ShrincsSigner;
  /// Main-key derivation index (the `seedByte` used at creation).
  derivationIndex: number;
  /// ERC-1271 verifier-key derivation index (distinct from `derivationIndex`).
  erc1271DerivationIndex: number;
  /// On-chain identity (CREATE3 salt).
  vaultId: Hex;
  maxSignatures: number;
  client: ShrincsWalletClient;
  walletAddress: Address;
}

export interface CreateFreshShrincsWalletOptions {
  /// Stateful budget baked into the main key + erc1271 key commitments. Keep
  /// small (e.g. 4) for fast keygen + lowest-unused-leaf scans.
  maxSignatures?: number;
  /// Anvil-funded wallet balance via `anvil_setBalance`. Default 10 ETH.
  walletBalance?: bigint;
  /// ETH pre-deposited at the EntryPoint via `EntryPoint.depositTo(wallet)`.
  /// Default 0n; set for ERC-4337 paths that pay prefund from the deposit.
  entryPointDeposit?: bigint;
}

/// Deploy a fresh ShrincsWallet through the SDK's `ShrincsFactoryClient`,
/// using the FE-derived-from-quantum-secret model: both the main key and the
/// dedicated ERC-1271 verifier key are derived from the SAME signer under
/// DISTINCT derivation indices (`derivationIndex` vs `erc1271DerivationIndex`).
/// `seedByte` parameterizes the quantum secret + both indices so each test
/// gets an isolated wallet whose key material doesn't collide with others.
export async function createFreshShrincsWallet(
  stack: ShrincsAnvilStack,
  seedByte: number,
  opts: CreateFreshShrincsWalletOptions = {}
): Promise<FreshShrincsWallet> {
  const maxSignatures = opts.maxSignatures ?? 4;
  const walletBalance = opts.walletBalance ?? parseEther("10");
  const entryPointDeposit = opts.entryPointDeposit ?? 0n;

  const signer = await makeShrincsSigner(seedByte);
  const derivationIndex = seedByte;
  const erc1271DerivationIndex = seedByte ^ 0xff;

  const factory = makeShrincsFactoryClient(stack);
  const client = await factory.createShrincsWallet({
    signer,
    maxSignatures,
    derivationIndex,
    erc1271: { derivationIndex: erc1271DerivationIndex, maxSignatures },
  });
  const walletAddress = client.walletAddress;

  if (walletBalance > 0n) {
    await stack.testClient.setBalance({
      address: walletAddress,
      value: walletBalance,
    });
  }
  if (entryPointDeposit > 0n) {
    const depHash = await stack.walletClient.writeContract({
      chain: foundry,
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "depositTo",
      args: [walletAddress],
      value: entryPointDeposit,
      account: stack.account,
    });
    await stack.publicClient.waitForTransactionReceipt({ hash: depHash });
  }

  return {
    signer,
    derivationIndex,
    erc1271DerivationIndex,
    vaultId: client.commitment,
    maxSignatures,
    client,
    walletAddress,
  };
}

// ─── Paymaster helpers ──────────────────────────────────────────────

/// Initialize the (already-deployed) paymaster proxy with `owner` and the full
/// verifier `publicKey` bundle — the contract derives the commitment and the
/// `maxSignatures` budget from the presented key material (they are never
/// trusted parameters). `paymaster` overrides the target (default: the shared
/// stack proxy) — pass a `deployFreshPaymasterProxy` address for tests that
/// must own their proxy's whole verifier lifecycle.
export async function initializePaymaster(
  stack: ShrincsAnvilStack,
  params: {
    owner: Address;
    publicKey: ShrincsPublicKey;
    hashSuite?: number;
    paymaster?: Address;
  }
): Promise<void> {
  const hash = await stack.walletClient.writeContract({
    chain: foundry,
    address: params.paymaster ?? stack.paymasterProxy,
    abi: shrincsPaymasterAbi,
    functionName: "initialize",
    args: [
      params.owner,
      publicKeyToAbi(params.publicKey),
      params.hashSuite ?? HASH_SUITE_KECCAK_256,
    ],
    account: stack.account,
  });
  await stack.publicClient.waitForTransactionReceipt({ hash });
}

/// Deploy a FRESH paymaster impl + ERC-1967 proxy (uninitialized), pinned to
/// the stack's shared SHRINCS verifier. The shared `stack.paymasterProxy` is
/// initialized once by whichever test claims it first; rotation/revocation
/// tests need a proxy whose epoch/bitmap state they fully own.
export async function deployFreshPaymasterProxy(
  stack: ShrincsAnvilStack
): Promise<Address> {
  const paymasterArtifact = readForgeArtifact(
    "out/ShrincsPaymaster.sol/ShrincsPaymaster.json"
  );
  const implHash = await stack.walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: paymasterArtifact.abi as any,
    bytecode: paymasterArtifact.bytecode.object as Hex,
    args: [stack.shrincsVerifier],
    account: stack.account,
    chain: foundry,
  });
  const implReceipt = await stack.publicClient.waitForTransactionReceipt({
    hash: implHash,
  });
  return deployErc1967Proxy(
    stack.walletClient,
    stack.publicClient,
    stack.account,
    implReceipt.contractAddress!
  );
}
