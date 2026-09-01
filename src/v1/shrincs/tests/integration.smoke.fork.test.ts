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
//
// FORK SMOKE: the executable proof that the SDK keeps existing V1.0.1-beta.2
// wallets working AND can upgrade them to the current implementation. Forks Base
// mainnet at a pinned block so the LIVE factory + deployed beta.2 implementation
// are present, then, entirely through the SDK's own code path:
//   1. deploys a beta.2 wallet through the LIVE factory (old 6-word init format,
//      built with a raw call — NOT the SDK deploy surface, which is new-format);
//   2. OPERATES it via `ShrincsWalletClient` (version-aware reads + a real signed
//      execute) — proving the SDK talks to deployed beta.2 bytecode;
//   3. UPGRADES it to this tree's implementation via `client.upgradeToAndCall`
//      (the 6-field blob the beta.2 caller forwards whole to the target's probe);
//   4. OPERATES the upgraded wallet again (fresh migrated key, bumped epoch).
//
// Requires `API_URL_BASE` (loaded from .env). Hard-fails if unset — this suite
// must run, never silently skip. Invoked by `npm run smoke:fork`.
import "dotenv/config";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, it, expect, beforeAll, afterAll } from "@jest/globals";
import {
  type Address,
  type Hex,
  type PublicClient,
  type TestClient,
  type WalletClient,
  createPublicClient,
  createTestClient,
  createWalletClient,
  encodeAbiParameters,
  getAddress,
  http,
  parseEther,
} from "viem";
import { base } from "viem/chains";
import { privateKeyToAccount, type PrivateKeyAccount } from "viem/accounts";
import { createAnvil, type Anvil } from "@viem/anvil";

import { walletFactoryAbi } from "../../abi/WalletFactory.js";
import {
  abiTuples,
  encodeInitPayload,
  publicKeyToAbi,
} from "../shrincsCodec.js";
import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import {
  SHRINCS_WALLET_BETA2_IMPLEMENTATION,
  getShrincsWalletAddress,
  v1Commitment,
} from "../addresses.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";
import { ShrincsWalletClient } from "../shrincsWalletClient.js";
import { shrincsWalletBeta2Abi } from "../versions/v1_0_1_beta2/abi.js";
import { resolveWalletVersion } from "../versions/index.js";

// ── Pinned fork constants (mirror test/fork/ForkUpgradeFromDeployed.t.sol) ──
const FORK_BLOCK_NUMBER = 50_754_000n;
// Live WalletFactory proxy (CreateX-deterministic; src/v1/addresses.json).
const FACTORY = "0xA2B2F71456a799FCf4EF7A3111c4B96b3e928cc8" as Address;
const FORK_PORT = 8564;
const CHAIN_ID = base.id;

// Anvil's first default funded account — the wallet owner + deployer here.
const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" as Hex;

const HASH_SUITE = HASH_SUITE_KECCAK_256;
const MAX_SIGS = 4;

interface ForgeArtifact {
  abi: unknown[];
  bytecode: { object: Hex };
  deployedBytecode: { object: Hex };
}

function readForgeArtifact(relativePath: string): ForgeArtifact {
  return JSON.parse(
    readFileSync(join(process.cwd(), relativePath), "utf8")
  ) as ForgeArtifact;
}

function requireForkUrl(): string {
  const url = process.env.API_URL_BASE;
  if (!url) {
    throw new Error(
      "API_URL_BASE is required for the fork smoke test (set it in .env); this suite must always run, never skip"
    );
  }
  return url;
}

/// The 32-byte commitment of a keypair bundle.
function commitmentOf(kp: ShrincsKeyPair): Hex {
  return kp.publicKeyCommitment;
}

/// Old-format (V1.0.1-beta.2) init payload: `(bytes32 commitment, bytes32 pkSeed,
/// PublicKey mainBundle, uint32 hashSuite, bytes32 erc1271Commitment, uint32
/// erc1271HashSuite)` — the ERC-1271 verifier is a BARE commitment, not a bundle.
function encodeBeta2InitPayload(params: {
  mainKey: ShrincsKeyPair;
  erc1271Commitment: Hex;
}): Hex {
  return encodeAbiParameters(
    [
      { name: "commitment", type: "bytes32" },
      { name: "pkSeed", type: "bytes32" },
      abiTuples.publicKey,
      { name: "hashSuite", type: "uint32" },
      { name: "erc1271Commitment", type: "bytes32" },
      { name: "erc1271HashSuite", type: "uint32" },
    ],
    [
      commitmentOf(params.mainKey),
      params.mainKey.publicKey.pkSeed,
      publicKeyToAbi(params.mainKey.publicKey),
      HASH_SUITE,
      params.erc1271Commitment,
      HASH_SUITE,
    ]
  );
}

describe("SDK fork smoke: operate + upgrade a live V1.0.1-beta.2 wallet", () => {
  let anvil: Anvil;
  let publicClient: PublicClient;
  let walletClient: WalletClient;
  let testClient: TestClient;
  let owner: PrivateKeyAccount;

  let signer: ShrincsSigner;
  let mainKey: ShrincsKeyPair;
  let walletAddress: Address;
  let client: ShrincsWalletClient;
  let shrincsVerifier: Address;

  const derivationIndex = 0x11;
  const erc1271Index = 0x22;

  beforeAll(async () => {
    const forkUrl = requireForkUrl();
    anvil = createAnvil({
      port: FORK_PORT,
      forkUrl,
      forkBlockNumber: FORK_BLOCK_NUMBER,
    });
    await anvil.start();

    const transport = http(`http://127.0.0.1:${anvil.port}`);
    owner = privateKeyToAccount(ANVIL_PRIV_KEY);
    publicClient = createPublicClient({ chain: base, transport }) as PublicClient;
    walletClient = createWalletClient({
      chain: base,
      transport,
      account: owner,
    }) as WalletClient;
    testClient = createTestClient({
      chain: base,
      mode: "anvil",
      transport,
    }) as TestClient;

    // Sanity: the fork actually carries the frozen beta.2 implementation.
    const latestImpl = (await publicClient.readContract({
      address: FACTORY,
      abi: walletFactoryAbi,
      functionName: "latestWalletImpl",
    })) as Address;
    expect(getAddress(latestImpl)).toBe(
      getAddress(SHRINCS_WALLET_BETA2_IMPLEMENTATION)
    );

    // ── Deploy a beta.2 wallet through the LIVE factory (old init format) ──
    signer = await ShrincsSigner.create(new Uint8Array(32).fill(0x5b));
    mainKey = signer.recoverKeyPair(derivationIndex, { maxSignatures: MAX_SIGS });
    const erc1271Key = signer.recoverKeyPair(erc1271Index, {
      maxSignatures: MAX_SIGS,
    });
    const mainCommitment = commitmentOf(mainKey);
    const erc1271Commitment = commitmentOf(erc1271Key);
    const identity = v1Commitment(
      mainCommitment,
      erc1271Commitment,
      owner.address
    );
    walletAddress = getShrincsWalletAddress(
      FACTORY,
      mainCommitment,
      erc1271Commitment,
      owner.address
    );

    const creationFee = (await publicClient.readContract({
      address: FACTORY,
      abi: walletFactoryAbi,
      functionName: "creationFee",
    })) as bigint;

    const deployHash = await walletClient.writeContract({
      chain: base,
      address: FACTORY,
      abi: walletFactoryAbi,
      functionName: "deployLatestWalletProxy",
      args: [
        identity,
        owner.address,
        encodeBeta2InitPayload({ mainKey, erc1271Commitment }),
      ],
      value: creationFee + parseEther("1"),
      account: owner,
    });
    await publicClient.waitForTransactionReceipt({ hash: deployHash });

    client = new ShrincsWalletClient({
      walletAddress,
      publicClient,
      walletClient,
      signer,
      commitment: mainCommitment,
      derivationIndex,
      chainId: CHAIN_ID,
      account: owner.address,
    });

    // The live pinned verifier the new implementation must also point at.
    shrincsVerifier = (await publicClient.readContract({
      address: walletAddress,
      abi: shrincsWalletBeta2Abi,
      functionName: "getShrincsVerifier",
    })) as Address;

    await testClient.setBalance({
      address: walletAddress,
      value: parseEther("10"),
    });
  }, 120_000);

  afterAll(async () => {
    await anvil?.stop();
  });

  it("1. deployed a real beta.2 wallet through the live factory", async () => {
    const code = await publicClient.getCode({ address: walletAddress });
    expect(code && code.length > 2).toBe(true);
    const impl = await client.resolveVersion();
    expect(impl.id).toBe("v1.0.1-beta.2");
  });

  it("2. OPERATES the beta.2 wallet via the SDK (version-aware reads + signed execute)", async () => {
    // Version-aware state read: beta.2 exposes `getErc1271Commitment`, not the
    // later `…PublicKeyCommitment`; a wrong getter would revert here.
    const before = await client.getWalletState();
    expect(before.shrincsPublicKeyCommitment.toLowerCase()).toBe(
      commitmentOf(mainKey).toLowerCase()
    );
    expect(before.keyVersion).toBe(0n);

    const recipient = "0x000000000000000000000000000000000000dEaD" as Address;
    await client.execute({ target: recipient, value: parseEther("0.01") });

    const after = await client.getWalletState();
    expect(after.actionNonce).toBe(before.actionNonce + 1n);
    expect(after.statefulLeavesUsed).toBe(before.statefulLeavesUsed + 1);
  }, 120_000);

  it("3. UPGRADES the beta.2 wallet to this tree's implementation via the SDK, WITH migration", async () => {
    // Deploy the current implementation, pinned to the same live verifier.
    const walletArtifact = readForgeArtifact(
      "out/ShrincsWallet.sol/ShrincsWallet.json"
    );
    const newImplHash = await walletClient.deployContract({
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      abi: walletArtifact.abi as any,
      bytecode: walletArtifact.bytecode.object,
      args: [FACTORY, shrincsVerifier],
      account: owner,
      chain: base,
    });
    const newImplReceipt = await publicClient.waitForTransactionReceipt({
      hash: newImplHash,
    });
    const newImplementation = getAddress(
      newImplReceipt.contractAddress as Address
    );
    // The new implementation is NOT a pinned `latest` address, so the resolver
    // treats it as the current (latest) surface.
    expect(resolveWalletVersion(newImplementation).id).toBe("latest");

    // Vet it as the LIVE factory owner (impersonated on the fork).
    const factoryOwner = (await publicClient.readContract({
      address: FACTORY,
      abi: walletFactoryAbi,
      functionName: "owner",
    })) as Address;
    await testClient.impersonateAccount({ address: factoryOwner });
    await testClient.setBalance({
      address: factoryOwner,
      value: parseEther("10"),
    });
    const vetHash = await walletClient.writeContract({
      chain: base,
      address: FACTORY,
      abi: walletFactoryAbi,
      functionName: "vetImplementation",
      args: [newImplementation],
      account: factoryOwner,
    });
    await publicClient.waitForTransactionReceipt({ hash: vetHash });
    await testClient.stopImpersonatingAccount({ address: factoryOwner });

    // Fresh key material for the migrating upgrade (new impl's `migrate`
    // requires strictly fresh trees), encoded in the NEW init format.
    const freshMain = signer.recoverKeyPair(0x33, { maxSignatures: MAX_SIGS });
    const freshErc1271 = signer.recoverKeyPair(0x44, {
      maxSignatures: MAX_SIGS,
    });
    const migratorPayload = encodeInitPayload({
      mainBundle: freshMain.publicKey,
      erc1271Bundle: freshErc1271.publicKey,
    });

    // THE MANDATE: upgrade the deployed beta.2 wallet through the SDK. The SDK
    // emits the 6-field blob; the beta.2 caller forwards it whole to the target
    // implementation's `verifyUpgrade` probe (the 0xc0 branch).
    await client.upgradeToAndCall({
      newImplementation,
      shouldMigrate: true,
      migratorPayload,
    });

    // The ERC-1967 pointer swapped and migrate bumped the epoch.
    const version = await client.resolveVersion();
    expect(version.id).toBe("latest");
    const state = await client.getWalletState();
    expect(state.keyVersion).toBe(1n);
    expect(state.shrincsPublicKeyCommitment.toLowerCase()).toBe(
      commitmentOf(freshMain).toLowerCase()
    );
  }, 180_000);

  it("4. OPERATES the UPGRADED wallet via the SDK (fresh migrated key, new surface)", async () => {
    // A client bound to the fresh migrated key operates the now-current wallet.
    const upgradedClient = new ShrincsWalletClient({
      walletAddress,
      publicClient,
      walletClient,
      signer,
      commitment: commitmentOf(
        signer.recoverKeyPair(0x33, { maxSignatures: MAX_SIGS })
      ),
      derivationIndex: 0x33,
      chainId: CHAIN_ID,
      account: owner.address,
    });

    const before = await upgradedClient.getWalletState();
    const recipient = "0x000000000000000000000000000000000000bEEF" as Address;
    await upgradedClient.execute({ target: recipient, value: parseEther("0.01") });
    const after = await upgradedClient.getWalletState();
    expect(after.actionNonce).toBe(before.actionNonce + 1n);
    expect(after.keyVersion).toBe(1n);
  }, 120_000);
});
