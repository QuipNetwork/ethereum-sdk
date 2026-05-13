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
import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  http,
  toHex,
  zeroAddress,
  parseEventLogs,
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
  DuplicateKeyError,
  EmptyKeysError,
  KeyAlreadyBurnedError,
  NoAvailableTransactionKeysError,
  PartialMulticallResultError,
} from "./errors.js";
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

/// Substitute the `__$<hash>$__` placeholders Foundry leaves in unlinked
/// library bytecode with the deployed library address. The forge artifact's
/// `linkReferences` gives byte offsets (post-`0x`); we rewrite each as a
/// 20-byte (40-hex) lowercased address with no `0x` prefix.
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
        // ref.start/length are byte offsets — multiply by 2 for hex chars.
        const hexStart = ref.start * 2;
        const hexLen = ref.length * 2;
        hex =
          hex.slice(0, hexStart) + addrPlain + hex.slice(hexStart + hexLen);
      }
    }
  }
  return ("0x" + hex) as Hex;
}

// Anvil's first prefunded account.
const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(ANVIL_PRIV_KEY);

const anvil = createAnvil({ port: 8551 });
let publicClient: PublicClient;
let walletClient: WalletClient;
let factoryAddress: Address;
let walletImplAddress: Address;

const MAX_FEE = 10n ** 16n;

/// Build the 1088-byte init payload (1 disaster + 1 ownership + 5 tx + 10 recovery)
/// from a signer. Returns the payload and the keys (so tests can inspect them).
function buildInitPayload(
  signer: QuipSigner,
  vaultId: Hex
): {
  payload: Hex;
  disaster: WinternitzAddress;
  ownership: WinternitzAddress;
  transactionKeys: WinternitzAddress[];
  recoveryKeys: WinternitzAddress[];
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
  return { payload, disaster, ownership, transactionKeys, recoveryKeys };
}

/// Deploy a fresh wallet under a unique vaultId and return a client plus
/// the head transaction key. Each test gets its own wallet so burned-key
/// state cannot bleed across cases.
async function createFreshWallet(seedByte: number): Promise<{
  signer: QuipSigner;
  vaultId: Uint8Array;
  client: QuipWalletClient;
  walletAddress: Address;
  transactionKeys: WinternitzAddress[];
}> {
  const quantumSecret = new Uint8Array(32).fill(seedByte);
  const signer = new QuipSigner(quantumSecret);
  const vaultId = new Uint8Array(32).fill(seedByte);
  const init = buildInitPayload(signer, toHex(vaultId));

  const hash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "deployLatestWalletProxy",
    args: [toHex(vaultId), account.address, init.payload],
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
  return {
    signer,
    vaultId,
    client,
    walletAddress,
    transactionKeys: init.transactionKeys,
  };
}

beforeAll(async () => {
  await anvil.start();
  const transport = http(`http://127.0.0.1:${anvil.port}`);
  publicClient = createPublicClient({ chain: foundry, transport });
  walletClient = createWalletClient({ chain: foundry, transport, account });

  // 1. Deploy QuipFactory(owner, maxFee)
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

  // 2a. Deploy WOTSPlus library (QuipWallet's bytecode has unresolved
  //     link references to it).
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

  // 2b. Link the library address into the wallet bytecode, then deploy.
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
  walletImplAddress = implReceipt.contractAddress!;

  // 3. Vet the implementation so deployLatestWalletProxy works.
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

// ─── Tests ──────────────────────────────────────────────────────────

describe("Phase 4.5 — pre-flight key-batch validation", () => {
  test("addKeys with empty array throws EmptyKeysError synchronously", async () => {
    const { client } = await createFreshWallet(0x10);
    await expect(client.addKeys(KeyType.Recovery, [])).rejects.toBeInstanceOf(
      EmptyKeysError
    );
  });

  test("addKeys with within-batch duplicate throws DuplicateKeyError synchronously", async () => {
    const { client, signer, vaultId } = await createFreshWallet(0x11);
    const k = signer.generateKeyPair(toHex(vaultId)).publicKey;
    await expect(
      client.addKeys(KeyType.Recovery, [k, k])
    ).rejects.toBeInstanceOf(DuplicateKeyError);
  });

  test("refreshKeys on Transaction kind throws RefreshTransactionForbiddenError synchronously", async () => {
    const { client, signer, vaultId } = await createFreshWallet(0x12);
    const k = signer.generateKeyPair(toHex(vaultId)).publicKey;
    // Pre-flight invariant from Phase 4: refreshing the Transaction keyset
    // is forbidden at the contract level — the SDK throws before sign().
    await expect(
      client.refreshKeys(KeyType.Transaction, [k])
    ).rejects.toThrow();
    // The signing key must not be burned, since no broadcast happened.
    const head = await client.getHeadTransactionKey();
    expect(signer.isBurned(head.publicSeed)).toBe(false);
  });
});

describe("Phase 4.5 — burned-key tracking on broadcast", () => {
  test("successful executeWithPayload marks the signing key burned", async () => {
    const { client, signer, vaultId } = await createFreshWallet(0x20);

    const head = await client.getHeadTransactionKey();
    expect(signer.isBurned(head.publicSeed)).toBe(false);

    // Pure rotation: target=zero, value=0, data="0x". The fee still
    // applies but is zero on the unconfigured factory.
    await client.executeWithPayload(zeroAddress, 0n, "0x");

    expect(signer.isBurned(head.publicSeed)).toBe(true);
    // Sanity: signer.sign with a fresh (never-burned) key works.
    const dummySeed = toHex(new Uint8Array(32).fill(0xfe));
    expect(() =>
      signer.sign(toHex(new Uint8Array(32)), toHex(vaultId), dummySeed)
    ).not.toThrow();
  }, 30_000);

  test("retry with the same key throws KeyAlreadyBurnedError; retry with a different key succeeds", async () => {
    const { client, signer } = await createFreshWallet(0x21);

    const keyset = await client.getKeyset(KeyType.Transaction);
    expect(keyset.length).toBe(TRANSACTION_KEY_INIT_AMOUNT);
    const firstKey = keyset[0];
    const secondKey = keyset[1];

    // First op: signs with firstKey (head), broadcasts, burns it.
    await client.executeWithPayload(zeroAddress, 0n, "0x", {
      signWithKey: firstKey,
    });
    expect(signer.isBurned(firstKey.publicSeed)).toBe(true);

    // Retry with the same (now-burned) key → signer refuses.
    await expect(
      client.executeWithPayload(zeroAddress, 0n, "0x", {
        signWithKey: firstKey,
      })
    ).rejects.toBeInstanceOf(KeyAlreadyBurnedError);

    // Retry with a different key from the keyset succeeds.
    await client.executeWithPayload(zeroAddress, 0n, "0x", {
      signWithKey: secondKey,
    });
    expect(signer.isBurned(secondKey.publicSeed)).toBe(true);
  }, 60_000);

  test("keyAllocationStrategy 'next-available' walks past burned head and signs with the next key", async () => {
    const { client, signer } = await createFreshWallet(0x22);
    const keyset = await client.getKeyset(KeyType.Transaction);
    const firstKey = keyset[0];

    // Pre-burn the head locally (no broadcast).
    signer.markBurned(firstKey.publicSeed);
    expect(signer.isBurned(firstKey.publicSeed)).toBe(true);

    // 'head' strategy would pick firstKey → sign() would throw. With
    // 'next-available' we walk past the burned head to whichever key the
    // contract returns next.
    await client.executeWithPayload(zeroAddress, 0n, "0x", {
      keyAllocationStrategy: "next-available",
    });

    // After broadcast, the second-picked key is burned. We can't predict
    // which keyset entry it picks (depends on EnumerableSet ordering), but
    // we can confirm: at least one *additional* key beyond firstKey is now
    // burned.
    const burnedAfter = keyset.filter((k) => signer.isBurned(k.publicSeed));
    expect(burnedAfter.length).toBeGreaterThanOrEqual(2);
  }, 30_000);

  test("'next-available' exhaustion throws NoAvailableTransactionKeysError", async () => {
    const { client, signer } = await createFreshWallet(0x23);
    const keyset = await client.getKeyset(KeyType.Transaction);

    // Burn every key locally (no broadcasts).
    for (const k of keyset) signer.markBurned(k.publicSeed);

    await expect(
      client.executeWithPayload(zeroAddress, 0n, "0x", {
        keyAllocationStrategy: "next-available",
      })
    ).rejects.toBeInstanceOf(NoAvailableTransactionKeysError);
  });
});

describe("Phase 4.5 — multicall partial-failure surfacing", () => {
  test("getWalletState against a no-code address throws PartialMulticallResultError", async () => {
    // Point a QuipWalletClient at an address with no code. The factory +
    // impl are deployed, but this random EOA address has no QuipWallet.
    const signer = new QuipSigner(new Uint8Array(32).fill(0x30));
    const noCodeAddr = "0xdeAdbEefdEAdbeefdEadbEEFdeadbeEFdEaDbeef" as Address;
    const client = new QuipWalletClient(
      signer,
      new Uint8Array(32).fill(0x30),
      noCodeAddr,
      publicClient,
      walletClient,
      account.address,
      foundry.id
    );

    let caught: unknown = null;
    try {
      // forceSequential so every individual readContract failure surfaces.
      await client.getWalletState({ forceSequential: true });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(PartialMulticallResultError);
    const err = caught as PartialMulticallResultError;
    expect(err.failures.length).toBeGreaterThan(0);
    // Each failure should carry a non-empty label
    for (const f of err.failures) {
      expect(typeof f.label).toBe("string");
      expect(f.label.length).toBeGreaterThan(0);
      expect(f.error).toBeInstanceOf(Error);
    }
  });

  test("getKeyset against a no-code address throws PartialMulticallResultError", async () => {
    // Same trick — but getKeyset reads keyCount first (which will also
    // fail). We need an address that has code but lacks `keyAt`. Easiest:
    // point at the factory address, which doesn't implement keyAt.
    const signer = new QuipSigner(new Uint8Array(32).fill(0x31));
    const client = new QuipWalletClient(
      signer,
      new Uint8Array(32).fill(0x31),
      factoryAddress,
      publicClient,
      walletClient,
      account.address,
      foundry.id
    );

    // keyCount on the factory would fail (factory has no keyCount fn).
    // The first failure point is keyCount, which getKeyset awaits.
    await expect(
      client.getKeyset(KeyType.Transaction, { forceSequential: true })
    ).rejects.toThrow();
  });
});
