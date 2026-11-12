// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// FORK SMOKE, V1.0.1-beta.3: the generation the live factory deploys today. It
// runs against the pre-0.4.0 verifier, so its STATELESS signatures are ABI
// structs, while this tree's implementation takes the fixed layout. This suite
// proves the SDK picks the right encoding from the wallet's installed
// implementation, before and after an upgrade:
//
//   1. a wallet created through the live factory resolves as beta.3;
//   2. ERC-1271 and recoverWallet work on it (ABI encoding);
//   3. the SDK upgrades it to this tree's implementation;
//   4. the SAME wallet then takes the fixed-layout ERC-1271 envelope, and the
//      old ABI-encoded signature is refused.
//
// Requires `API_URL_BASE` (never skips), like `integration.smoke.fork.test.ts`.

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
  http,
  parseEther,
  size,
} from "viem";
import { base } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { createAnvil, type Anvil } from "@viem/anvil";

import { SHRINCS_WALLET_BETA3_IMPLEMENTATION } from "../addresses.js";
import { ERC1271_SIGNATURE_BYTES } from "../constants.js";
import { ShrincsFactoryClient } from "../shrincsFactoryClient.js";
import { type ShrincsKeyPair, type ShrincsSigner } from "../shrincsSigner.js";
import { type ShrincsWalletClient } from "../shrincsWalletClient.js";
import {
  deployAndVetCurrentImplementation,
  makeShrincsSigner,
} from "./utils/shrincsAnvilFixture.js";

// A Base mainnet block at which the live factory's `latestWalletImpl` is beta.3.
const FORK_BLOCK_NUMBER = 56_482_000n;
// Live WalletFactory proxy (CreateX-deterministic; src/v1/addresses.json).
const FACTORY = "0xA2B2F71456a799FCf4EF7A3111c4B96b3e928cc8" as Address;
const FORK_PORT = 8565;
const MAX_SIGS = 8;
const SEED = 0x7b;
const ERC1271_INDEX = 0x7c;
const HASH = ("0x" + "33".repeat(32)) as Hex;

describe("SDK fork smoke: operate + upgrade a live V1.0.1-beta.3 wallet", () => {
  const owner = privateKeyToAccount(
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
  );

  let anvil: Anvil;
  let publicClient: PublicClient;
  let walletClient: WalletClient;
  let testClient: TestClient;
  let signer: ShrincsSigner;
  let erc1271KeyPair: ShrincsKeyPair;
  let client: ShrincsWalletClient;
  let abiEncodedSignature: Hex;

  beforeAll(async () => {
    const forkUrl = process.env.API_URL_BASE;
    if (!forkUrl) {
      throw new Error("API_URL_BASE is required for the fork smoke test (set it in .env)");
    }
    anvil = createAnvil({ port: FORK_PORT, forkUrl, forkBlockNumber: FORK_BLOCK_NUMBER });
    await anvil.start();
    const transport = http(`http://127.0.0.1:${anvil.port}`);
    publicClient = createPublicClient({ chain: base, transport }) as PublicClient;
    walletClient = createWalletClient({ chain: base, transport, account: owner }) as WalletClient;
    testClient = createTestClient({ chain: base, mode: "anvil", transport }) as TestClient;
    await testClient.setBalance({ address: owner.address, value: parseEther("100") });

    signer = await makeShrincsSigner(SEED);
    erc1271KeyPair = signer.recoverKeyPair(ERC1271_INDEX, { maxSignatures: MAX_SIGS });
    client = await new ShrincsFactoryClient({
      publicClient,
      walletClient,
      account: owner.address,
      chainId: base.id,
      factoryAddress: FACTORY,
      walletImplementation: SHRINCS_WALLET_BETA3_IMPLEMENTATION,
    }).createShrincsWallet({
      signer,
      maxSignatures: MAX_SIGS,
      derivationIndex: SEED,
      erc1271: { derivationIndex: ERC1271_INDEX, maxSignatures: MAX_SIGS },
    });
    await testClient.setBalance({ address: client.walletAddress, value: parseEther("10") });
  }, 180_000);

  afterAll(async () => {
    await anvil?.stop();
  });

  it("1. a wallet created through the live factory resolves as beta.3", async () => {
    const version = await client.resolveVersion();
    expect(version.id).toBe("v1.0.1-beta.3");
    expect(version.quirks.statelessSignatureEncoding).toBe("abiStruct");
  });

  it("2. ERC-1271 and recoverWallet work on beta.3 (stateless signatures as ABI structs)", async () => {
    abiEncodedSignature = await client.signErc1271({ hash: HASH, erc1271KeyPair, owner });
    expect(size(abiEncodedSignature)).toBeGreaterThan(ERC1271_SIGNATURE_BYTES);
    expect(await client.isValidSignature(HASH, abiEncodedSignature)).toBe(true);

    // Rolled back so the upgrade below still starts from the original key.
    const snapshot = await testClient.snapshot();
    try {
      const nextKey = (await makeShrincsSigner(SEED + 1)).recoverKeyPair(SEED + 1, {
        maxSignatures: MAX_SIGS,
      });
      const receipt = await client.recoverWallet({ nextKey: nextKey.publicKey });
      expect(receipt.status).toBe("success");
      expect((await client.getWalletState()).shrincsPublicKeyCommitment.toLowerCase()).toBe(
        nextKey.publicKeyCommitment.toLowerCase()
      );
    } finally {
      await testClient.revert({ id: snapshot });
    }
  }, 180_000);

  it("3. the SDK upgrades the beta.3 wallet to this tree's implementation", async () => {
    const newImplementation = await deployAndVetCurrentImplementation({
      publicClient,
      walletClient,
      testClient,
      deployer: owner,
      chain: base,
      factory: FACTORY,
    });
    await client.upgradeToAndCall({ newImplementation });
    const version = await client.resolveVersion();
    expect(version.id).toBe("latest");
    expect(version.quirks.statelessSignatureEncoding).toBe("fixedLayout");
  }, 180_000);

  it("4. the upgraded wallet takes the fixed-layout ERC-1271 envelope and refuses the ABI one", async () => {
    expect(await client.getErc1271Version()).toBe(1);
    const envelope = await client.signErc1271({ hash: HASH, erc1271KeyPair, owner });
    expect(size(envelope)).toBe(ERC1271_SIGNATURE_BYTES);
    expect(await client.isValidSignature(HASH, envelope)).toBe(true);
    expect(await client.isValidSignature(HASH, abiEncodedSignature)).toBe(false);
  }, 180_000);
});
