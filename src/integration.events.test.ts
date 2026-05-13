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
import { describe, test, expect, beforeAll, afterAll } from "@jest/globals";
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
  parseEventLogs,
  parseEther,
  toHex,
  zeroAddress,
} from "viem";
import { createAnvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { quipFactoryAbi } from "./abi/QuipFactory.js";
import { QuipSigner } from "./signer.js";
import { QuipWalletClient, KeyType } from "./walletClient.js";
import {
  parseExecutionSucceeded,
  parseKeyReplaced,
  parseKeyRotated,
  parseKeyRotationOnly,
  parseKeysAdded,
  parseKeysRefreshed,
  parseQuipCreated,
  parseWalletInitialized,
  parseWalletReceipt,
} from "./events.js";
import {
  encodeInit,
  type WinternitzAddress,
  TRANSACTION_KEY_INIT_AMOUNT,
  RECOVERY_KEY_AMOUNT,
} from "./wotsCodec.js";

// ─── Forge artifacts ────────────────────────────────────────────────
const factoryArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/QuipFactory.sol/QuipFactory.json"),
    "utf8"
  )
);
const factoryBytecode = factoryArtifact.bytecode.object as Hex;

const walletArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/QuipWallet.sol/QuipWallet.json"),
    "utf8"
  )
);
const walletUnlinkedBytecode = walletArtifact.bytecode.object as string;
const quipWalletDeployAbi = walletArtifact.abi;

const wotsPlusArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/WOTSPlus.sol/WOTSPlus.json"),
    "utf8"
  )
);
const wotsPlusBytecode = wotsPlusArtifact.bytecode.object as Hex;
const wotsPlusAbi = wotsPlusArtifact.abi;

function linkWalletBytecode(libAddress: Address): Hex {
  const refs =
    walletArtifact.bytecode.linkReferences as Record<
      string,
      Record<string, Array<{ start: number; length: number }>>
    >;
  let hex = walletUnlinkedBytecode.replace(/^0x/, "");
  const addrPlain = libAddress.replace(/^0x/, "").toLowerCase();
  for (const file of Object.values(refs)) {
    for (const libRefs of Object.values(file)) {
      for (const ref of libRefs) {
        const hexStart = ref.start * 2;
        const hexLen = ref.length * 2;
        hex =
          hex.slice(0, hexStart) + addrPlain + hex.slice(hexStart + hexLen);
      }
    }
  }
  return ("0x" + hex) as Hex;
}

const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(ANVIL_PRIV_KEY);

const anvil = createAnvil({ port: 8554 });
let publicClient: PublicClient;
let walletClient: WalletClient;
let testClient: TestClient;
let factoryAddress: Address;

const MAX_FEE = 10n ** 16n;

function buildInitPayload(
  signer: QuipSigner,
  vaultId: Hex
): {
  payload: Hex;
  transactionKeys: WinternitzAddress[];
  recoveryKeys: WinternitzAddress[];
  disaster: WinternitzAddress;
  ownership: WinternitzAddress;
} {
  const disaster = signer.generateKeyPair(vaultId).publicKey;
  const ownership = signer.generateKeyPair(vaultId).publicKey;
  const transactionKeys = Array.from(
    { length: TRANSACTION_KEY_INIT_AMOUNT },
    () => signer.generateKeyPair(vaultId).publicKey
  );
  const recoveryKeys = Array.from({ length: RECOVERY_KEY_AMOUNT }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  const payload = encodeInit(disaster, ownership, transactionKeys, recoveryKeys);
  return { payload, transactionKeys, recoveryKeys, disaster, ownership };
}

async function createFreshWallet(seedByte: number): Promise<{
  signer: QuipSigner;
  vaultId: Hex;
  client: QuipWalletClient;
  walletAddress: Address;
  creationReceipt: Awaited<
    ReturnType<PublicClient["waitForTransactionReceipt"]>
  >;
  init: ReturnType<typeof buildInitPayload>;
}> {
  const quantumSecret = new Uint8Array(32).fill(seedByte);
  const signer = new QuipSigner(quantumSecret);
  const vaultId = toHex(new Uint8Array(32).fill(seedByte));
  const init = buildInitPayload(signer, vaultId);

  const hash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "deployLatestWalletProxy",
    args: [vaultId, account.address, init.payload],
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const logs = parseEventLogs({
    abi: quipFactoryAbi,
    logs: receipt.logs,
    eventName: "QuipCreated",
  });
  const walletAddress = logs[0].args.quip;

  const client = new QuipWalletClient(
    signer,
    vaultId,
    walletAddress,
    publicClient,
    walletClient,
    account.address,
    foundry.id
  );
  return { signer, vaultId, client, walletAddress, creationReceipt: receipt, init };
}

beforeAll(async () => {
  await anvil.start();
  const transport = http(`http://127.0.0.1:${anvil.port}`);
  publicClient = createPublicClient({ chain: foundry, transport });
  walletClient = createWalletClient({ chain: foundry, transport, account });
  testClient = createTestClient({
    chain: foundry,
    mode: "anvil",
    transport,
  });

  // 1. Deploy QuipFactory.
  const factoryHash = await walletClient.deployContract({
    abi: quipFactoryAbi,
    bytecode: factoryBytecode,
    args: [account.address, MAX_FEE],
    account,
    chain: foundry,
  });
  const factoryReceipt = await publicClient.waitForTransactionReceipt({
    hash: factoryHash,
  });
  factoryAddress = factoryReceipt.contractAddress!;

  // 2a. Deploy WOTSPlus library.
  const wotsHash = await walletClient.deployContract({
    abi: wotsPlusAbi,
    bytecode: wotsPlusBytecode,
    account,
    chain: foundry,
  });
  const wotsReceipt = await publicClient.waitForTransactionReceipt({
    hash: wotsHash,
  });
  const wotsPlusAddress = wotsReceipt.contractAddress!;

  // 2b. Link + deploy wallet impl.
  const walletBytecode = linkWalletBytecode(wotsPlusAddress);
  const implHash = await walletClient.deployContract({
    abi: quipWalletDeployAbi,
    bytecode: walletBytecode,
    args: [factoryAddress],
    account,
    chain: foundry,
  });
  const implReceipt = await publicClient.waitForTransactionReceipt({
    hash: implHash,
  });
  const walletImplAddress = implReceipt.contractAddress!;

  // 3. Vet so deployLatestWalletProxy works.
  const vetHash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "vetImplementation",
    args: [walletImplAddress],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: vetHash });
}, 60_000);

afterAll(async () => {
  await anvil.stop().catch(() => {});
}, 10_000);

describe("Factory event parsers", () => {
  test("parseQuipCreated decodes deployLatestWalletProxy receipt", async () => {
    const { creationReceipt, walletAddress, init } =
      await createFreshWallet(0xc0);
    const events = parseQuipCreated(creationReceipt);
    expect(events).toHaveLength(1);
    expect(events[0].creator.toLowerCase()).toBe(
      account.address.toLowerCase()
    );
    expect(events[0].quip.toLowerCase()).toBe(walletAddress.toLowerCase());
    expect(events[0].disasterRecoveryKey.publicSeed).toBe(
      init.disaster.publicSeed
    );
  }, 30_000);
});

describe("Wallet event parsers — execution path", () => {
  test("parseWalletReceipt → 'executed' on successful ETH transfer", async () => {
    const { client, walletAddress } = await createFreshWallet(0xc1);
    // Fund the wallet so it can actually transfer something.
    await testClient.setBalance({
      address: walletAddress,
      value: parseEther("1"),
    });
    const recipient = "0x000000000000000000000000000000000000DEAd" as const;
    const receipt = await client.executeWithPayload(recipient, 100n, "0x");
    const result = parseWalletReceipt(receipt);
    if (result === null) throw new Error("expected non-null");
    if (result.kind !== "executed")
      throw new Error(`expected executed, got ${result.kind}`);
    expect(result.target.toLowerCase()).toBe(recipient.toLowerCase());
    expect(result.value).toBe(100n);
    // ExecutionSucceeded + KeyRotated both present.
    expect(parseExecutionSucceeded(receipt)).toHaveLength(1);
    expect(parseKeyRotated(receipt)).toHaveLength(1);
    expect(result.rotation.oldKey.publicSeed).not.toBe(
      result.rotation.newKey.publicSeed
    );
  }, 30_000);

  test("parseWalletReceipt → 'rotation-only' for execute(zero, 0, '0x')", async () => {
    const { client } = await createFreshWallet(0xc2);
    const receipt = await client.executeWithPayload(zeroAddress, 0n, "0x");
    const result = parseWalletReceipt(receipt);
    if (result === null) throw new Error("expected non-null");
    expect(result.kind).toBe("rotation-only");
    expect(parseKeyRotationOnly(receipt)).toHaveLength(1);
    expect(parseExecutionSucceeded(receipt)).toHaveLength(0);
  }, 30_000);

  // Note: the contract does not currently emit `ExecutionReverted` —
  // `LibCall.callContract` bubbles inner reverts so the whole `execute(bytes)`
  // reverts together. The event is declared in `IQuipWallet.sol` as
  // future-ready (for an ERC-4337 path where the wallet absorbs inner reverts
  // while still committing key rotation). The parser + `decodedReason` chain
  // is covered by `src/events.test.ts`; no live integration trigger exists
  // until the contract starts emitting it.
});

describe("Wallet event parsers — key management", () => {
  test("parseKeysAdded decodes addKeys receipt", async () => {
    const { client, signer, vaultId } = await createFreshWallet(0xc4);
    // Recovery keyset starts at full capacity (10). Use the Verification
    // keyset which starts empty.
    const newKeys = [
      signer.generateKeyPair(toHex(vaultId)).publicKey,
      signer.generateKeyPair(toHex(vaultId)).publicKey,
    ];
    const receipt = await client.addKeys(KeyType.Verification, newKeys);
    const events = parseKeysAdded(receipt);
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe(KeyType.Verification);
    expect(events[0].count).toBe(2n);
    // KeyRotated also emitted (the signing tx key rotated).
    expect(parseKeyRotated(receipt)).toHaveLength(1);
  }, 30_000);

  test("parseKeysRefreshed decodes refreshKeys receipt", async () => {
    const { client, signer, vaultId } = await createFreshWallet(0xc5);
    const newRecovery = Array.from({ length: 3 }, () =>
      signer.generateKeyPair(toHex(vaultId)).publicKey
    );
    const receipt = await client.refreshKeys(KeyType.Recovery, newRecovery);
    const events = parseKeysRefreshed(receipt);
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe(KeyType.Recovery);
  }, 30_000);

  test("parseKeyReplaced decodes replaceKeyAt receipt", async () => {
    const { client, signer, vaultId } = await createFreshWallet(0xc6);
    const newKey = signer.generateKeyPair(toHex(vaultId)).publicKey;
    const receipt = await client.replaceKeyAt(KeyType.Recovery, 0n, newKey);
    const events = parseKeyReplaced(receipt);
    expect(events).toHaveLength(1);
    expect(events[0].kind).toBe(KeyType.Recovery);
    expect(events[0].index).toBe(0n);
    expect(events[0].newKey.publicSeed).toBe(newKey.publicSeed);
  }, 30_000);
});

describe("parseWalletInitialized", () => {
  test("decodes the WalletInitialized log from a fresh wallet's creation receipt", async () => {
    const { creationReceipt, init } = await createFreshWallet(0xc7);
    const events = parseWalletInitialized(creationReceipt);
    expect(events).toHaveLength(1);
    expect(events[0].owner.toLowerCase()).toBe(
      account.address.toLowerCase()
    );
    expect(events[0].transactionKeys).toHaveLength(TRANSACTION_KEY_INIT_AMOUNT);
    expect(events[0].recoveryKeys).toHaveLength(RECOVERY_KEY_AMOUNT);
    expect(events[0].transactionKeys[0].publicSeed).toBe(
      init.transactionKeys[0].publicSeed
    );
  }, 30_000);
});
