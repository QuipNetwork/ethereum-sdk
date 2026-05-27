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
  createPublicClient,
  createWalletClient,
  http,
  size,
  toHex,
  getAddress,
} from "viem";
import { createAnvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  type WinternitzAddress,
  type WinternitzElements,
  KeyType,
  encodeInit,
  encodeExecute,
  encodeRecoverWallet,
  encodeKeyManagement,
  encodeWithdrawDeposit,
  encodeReplaceKeyAt,
  encodeUserOpSignature,
  encodeSaveWallet,
  encodeOwnershipTransfer,
  encodeUpgradeToAndCall,
  encodeRecoveryUpgrade,
  saveWalletKeysHash,
  ownershipTransferKeysHash,
  decodeInit,
  decodeExecute,
  decodeRecoverWallet,
  decodeKeyManagement,
  decodeWithdrawDeposit,
  decodeReplaceKeyAt,
  decodeUserOpSignature,
  decodeSaveWallet,
  decodeOwnershipTransfer,
  decodeUpgradeToAndCall,
  decodeRecoveryUpgrade,
  executeDigest,
  keysetDigest,
  recoverWalletDigest,
  withdrawDepositDigest,
  replaceKeyAtDigest,
  upgradeDigest,
  verificationDigest,
  upgradeRecoveryDigest,
  erc4337ExecuteDigest,
  saveWalletDigest,
  transferOwnershipDigest,
  completeOwnershipHandoverDigest,
  RECOVERY_KEY_AMOUNT,
  TRANSACTION_KEY_INIT_AMOUNT,
  SAVE_WALLET_PAYLOAD_SIZE,
  OWNERSHIP_TRANSFER_PAYLOAD_SIZE,
  UPGRADE_PAYLOAD_SIZE,
  RECOVERY_UPGRADE_PAYLOAD_SIZE,
} from "../wotsCodec.js";

// ─── Harness artifact (from forge build output) ──────────────────
const artifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/WOTSPlusCodecHarness.sol/WOTSPlusCodecHarness.json"),
    "utf8",
  ),
);
const harnessAbi = artifact.abi;
const harnessBytecode = artifact.bytecode.object as Hex;

// ─── Test helpers (mirror Solidity _makeKeyAndSig) ───────────────

function makeKey(seed: bigint): WinternitzAddress {
  return {
    publicSeed: toHex(seed, { size: 32 }),
    publicKeyHash: toHex(seed + 1n, { size: 32 }),
  };
}

function makeSig(seed: bigint): WinternitzElements {
  return {
    elements: Array.from({ length: 67 }, (_, i) =>
      toHex(seed + 100n + BigInt(i), { size: 32 }),
    ),
  };
}

// ─── Anvil + harness deployment ──────────────────────────────────

const anvil = createAnvil();
let harnessAddress: Address;
let client: PublicClient;

beforeAll(async () => {
  await anvil.start();

  const transport = http(`http://127.0.0.1:${anvil.port}`);
  client = createPublicClient({ chain: foundry, transport });

  const walletClient = createWalletClient({
    chain: foundry,
    transport,
    account: privateKeyToAccount(
      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    ),
  });

  const hash = await walletClient.deployContract({
    abi: harnessAbi,
    bytecode: harnessBytecode,
  });
  const receipt = await client.waitForTransactionReceipt({ hash });
  harnessAddress = receipt.contractAddress!;
}, 30_000);

afterAll(async () => {
  await anvil.stop().catch(() => {});
}, 10_000);

async function callHarness(functionName: string, args: unknown[]): Promise<Hex> {
  return client.readContract({
    address: harnessAddress,
    abi: harnessAbi,
    functionName,
    args,
  }) as Promise<Hex>;
}

// ─── Digest test constants ───────────────────────────────────────

const WALLET: Address = "0x0000000000000000000000000000000000000001";
const CHAIN_ID = 1n;
const S1: Hex = toHex(10n, { size: 32 });
const H1: Hex = toHex(11n, { size: 32 });
const S2: Hex = toHex(12n, { size: 32 });
const H2: Hex = toHex(13n, { size: 32 });
const S3: Hex = toHex(14n, { size: 32 });
const H3: Hex = toHex(15n, { size: 32 });
const TARGET: Address = "0x0000000000000000000000000000000000000002";
const IMPL: Address = "0x0000000000000000000000000000000000000003";
const VALUE = 1000n;
const OPDATA_HASH: Hex = toHex(99n, { size: 32 });
const KEYS_HASH: Hex = toHex(88n, { size: 32 });
const USER_OP_HASH: Hex = toHex(77n, { size: 32 });

// ─── Encoder parity tests (live Solidity comparison) ─────────────

describe("encoder parity (live Solidity)", () => {
  const cur = makeKey(1n);
  const next = makeKey(3n);
  const sig = makeSig(1n);

  test("encodeExecute matches Solidity", async () => {
    const tsEncoded = encodeExecute(cur, next, sig, TARGET, VALUE, "0xdeadbeef");
    const solEncoded = await callHarness("exposed_encodeExecute", [
      cur, next, sig, TARGET, VALUE, "0xdeadbeef",
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeRecoverWallet matches Solidity", async () => {
    const recovery = makeKey(5n);
    const newRecovery = makeKey(7n);
    const newTransaction = makeKey(9n);
    const tsEncoded = encodeRecoverWallet(recovery, newRecovery, newTransaction, sig);
    const solEncoded = await callHarness("exposed_encodeRecoverWallet", [
      recovery, newRecovery, newTransaction, sig,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeKeyManagement matches Solidity", async () => {
    const keys: WinternitzAddress[] = [makeKey(200n), makeKey(202n)];
    const tsEncoded = encodeKeyManagement(KeyType.Recovery, cur, next, sig, keys);
    const solEncoded = await callHarness("exposed_encodeKeyManagement", [
      KeyType.Recovery, cur, next, sig, keys,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeWithdrawDeposit matches Solidity", async () => {
    const tsEncoded = encodeWithdrawDeposit(cur, next, sig, TARGET, VALUE);
    const solEncoded = await callHarness("exposed_encodeWithdrawDeposit", [
      cur, next, sig, TARGET, VALUE,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeReplaceKeyAt matches Solidity", async () => {
    const newKey = makeKey(42n);
    const tsEncoded = encodeReplaceKeyAt(KeyType.Recovery, cur, next, sig, 3n, newKey);
    const solEncoded = await callHarness("exposed_encodeReplaceKeyAt", [
      KeyType.Recovery, cur, next, sig, 3n, newKey,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeUserOpSignature matches Solidity", async () => {
    const tsEncoded = encodeUserOpSignature(cur, next, sig);
    const solEncoded = await callHarness("exposed_encodeUserOpSignature", [
      cur, next, sig,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeSaveWallet matches Solidity", async () => {
    const currentDisaster = makeKey(900n);
    const newDisaster = makeKey(902n);
    const newTransactionKeys = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      (_, i) => makeKey(BigInt(1000 + i * 2))
    );
    const newRecoveryKeys = Array.from(
      { length: RECOVERY_KEY_AMOUNT },
      (_, i) => makeKey(BigInt(2000 + i * 2))
    );
    const tsEncoded = encodeSaveWallet(
      currentDisaster,
      newDisaster,
      sig,
      newTransactionKeys,
      newRecoveryKeys
    );
    const solEncoded = await callHarness("exposed_encodeSaveWallet", [
      currentDisaster,
      newDisaster,
      sig,
      newTransactionKeys,
      newRecoveryKeys,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeOwnershipTransfer matches Solidity", async () => {
    const currentOwnership = makeKey(800n);
    const newOwnership = makeKey(802n);
    const newDisaster = makeKey(804n);
    const newTransactionKeys = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      (_, i) => makeKey(BigInt(3000 + i * 2))
    );
    const newRecoveryKeys = Array.from(
      { length: RECOVERY_KEY_AMOUNT },
      (_, i) => makeKey(BigInt(4000 + i * 2))
    );
    const tsEncoded = encodeOwnershipTransfer(
      currentOwnership,
      newOwnership,
      sig,
      TARGET,
      newDisaster,
      newTransactionKeys,
      newRecoveryKeys
    );
    const solEncoded = await callHarness("exposed_encodeOwnershipTransfer", [
      currentOwnership,
      newOwnership,
      sig,
      TARGET,
      newDisaster,
      newTransactionKeys,
      newRecoveryKeys,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeRecoveryUpgrade matches Solidity", async () => {
    const verifier = makeKey(500n);
    const verifySig = makeSig(500n);
    const tsEncoded = encodeRecoveryUpgrade(cur, next, sig, verifier, verifySig);
    const solEncoded = await callHarness("exposed_encodeRecoveryUpgrade", [
      cur, next, sig, verifier, verifySig,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeUpgradeToAndCall (no migrate) matches Solidity", async () => {
    const verifier = makeKey(600n);
    const verifySig = makeSig(600n);
    const zeroMigrator: Hex = `0x${"00".repeat(1088)}`;
    const tsEncoded = encodeUpgradeToAndCall(
      cur,
      next,
      sig,
      verifier,
      verifySig,
      false,
      "0x"
    );
    const solEncoded = await callHarness("exposed_encodeUpgradeToAndCall", [
      cur,
      next,
      sig,
      verifier,
      verifySig,
      false,
      zeroMigrator,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeUpgradeToAndCall (with migrate) matches Solidity", async () => {
    const verifier = makeKey(700n);
    const verifySig = makeSig(700n);
    // Build a valid 1088-byte init layout (disaster + ownership + 5 txn + 10 recovery).
    const initDisaster = makeKey(7000n);
    const initOwnership = makeKey(7002n);
    const initTxn = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      (_, i) => makeKey(BigInt(7100 + i * 2))
    );
    const initRecovery = Array.from(
      { length: RECOVERY_KEY_AMOUNT },
      (_, i) => makeKey(BigInt(7200 + i * 2))
    );
    const migrator = encodeInit(initDisaster, initOwnership, initTxn, initRecovery);
    expect(size(migrator)).toBe(1088);

    const tsEncoded = encodeUpgradeToAndCall(
      cur,
      next,
      sig,
      verifier,
      verifySig,
      true,
      migrator
    );
    const solEncoded = await callHarness("exposed_encodeUpgradeToAndCall", [
      cur, next, sig, verifier, verifySig, true, migrator,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });
});

// ─── Digest parity tests (live Solidity comparison) ──────────────

describe("digest parity (live Solidity)", () => {
  test("executeDigest matches Solidity", async () => {
    const FEE = 1000n;
    const tsDigest = executeDigest(
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, VALUE, OPDATA_HASH, FEE,
    );
    const solDigest = await callHarness("exposed_executeDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, VALUE, OPDATA_HASH, FEE,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("keysetDigest matches Solidity for each (kind, replace)", async () => {
    for (const kind of [KeyType.Transaction, KeyType.Recovery, KeyType.Verification]) {
      for (const replace of [false, true]) {
        const tsDigest = keysetDigest(kind, replace, WALLET, CHAIN_ID, S1, H1, S2, H2, KEYS_HASH);
        const solDigest = await callHarness("exposed_keysetDigest", [
          kind, replace, WALLET, CHAIN_ID, S1, H1, S2, H2, KEYS_HASH,
        ]);
        expect(tsDigest).toBe(solDigest);
      }
    }
  });

  test("keysetDigest produces distinct values across (kind, replace) tuples", () => {
    const digests = new Set<string>();
    for (const kind of [KeyType.Transaction, KeyType.Recovery, KeyType.Verification]) {
      for (const replace of [false, true]) {
        digests.add(
          keysetDigest(kind, replace, WALLET, CHAIN_ID, S1, H1, S2, H2, KEYS_HASH)
        );
      }
    }
    // 6 combinations, but refresh-Transaction collapses onto add-Transaction
    // (the `replace` bit is intentionally ignored for Transaction since
    // refresh-Transaction is contract-forbidden), so 5 distinct values.
    expect(digests.size).toBe(5);
  });

  test("recoverWalletDigest matches Solidity", async () => {
    const tsDigest = recoverWalletDigest(
      WALLET, CHAIN_ID, S1, H1, S2, H2, S3, H3,
    );
    const solDigest = await callHarness("exposed_recoverWalletDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2, S3, H3,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("withdrawDepositDigest matches Solidity", async () => {
    const AMOUNT = 5n * 10n ** 18n;
    const tsDigest = withdrawDepositDigest(
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, AMOUNT,
    );
    const solDigest = await callHarness("exposed_withdrawDepositDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, AMOUNT,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("replaceKeyAtDigest matches Solidity for each kind", async () => {
    const NEW_SEED = toHex(101n, { size: 32 });
    const NEW_HASH = toHex(102n, { size: 32 });
    for (const kind of [KeyType.Transaction, KeyType.Recovery, KeyType.Verification]) {
      const tsDigest = replaceKeyAtDigest(
        kind, WALLET, CHAIN_ID, S1, H1, S2, H2, 7n, NEW_SEED, NEW_HASH,
      );
      const solDigest = await callHarness("exposed_replaceKeyAtDigest", [
        kind, WALLET, CHAIN_ID, S1, H1, S2, H2, 7n, NEW_SEED, NEW_HASH,
      ]);
      expect(tsDigest).toBe(solDigest);
    }
  });

  test("upgradeDigest matches Solidity", async () => {
    const tsDigest = upgradeDigest(WALLET, CHAIN_ID, IMPL, S1, H1, S2, H2);
    const solDigest = await callHarness("exposed_upgradeDigest", [
      WALLET, CHAIN_ID, IMPL, S1, H1, S2, H2,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("verificationDigest matches Solidity", async () => {
    const tsDigest = verificationDigest(WALLET, CHAIN_ID, IMPL, S1, H1);
    const solDigest = await callHarness("exposed_verificationDigest", [
      WALLET, CHAIN_ID, IMPL, S1, H1,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("upgradeRecoveryDigest matches Solidity", async () => {
    const tsDigest = upgradeRecoveryDigest(WALLET, CHAIN_ID, IMPL, S1, H1, S2, H2);
    const solDigest = await callHarness("exposed_upgradeRecoveryDigest", [
      WALLET, CHAIN_ID, IMPL, S1, H1, S2, H2,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("erc4337ExecuteDigest matches Solidity", async () => {
    const FEE = 1000n;
    const tsDigest = erc4337ExecuteDigest(
      WALLET, CHAIN_ID, S1, H1, S2, H2, USER_OP_HASH, FEE,
    );
    const solDigest = await callHarness("exposed_erc4337ExecuteDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2, USER_OP_HASH, FEE,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("saveWalletDigest matches Solidity", async () => {
    const tsDigest = saveWalletDigest(
      WALLET, CHAIN_ID, S1, H1, S2, H2, KEYS_HASH,
    );
    const solDigest = await callHarness("exposed_saveWalletDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2, KEYS_HASH,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("transferOwnershipDigest matches Solidity", async () => {
    const tsDigest = transferOwnershipDigest(
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, KEYS_HASH,
    );
    const solDigest = await callHarness("exposed_transferOwnershipDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, KEYS_HASH,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("completeOwnershipHandoverDigest matches Solidity", async () => {
    const tsDigest = completeOwnershipHandoverDigest(
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, KEYS_HASH,
    );
    const solDigest = await callHarness("exposed_completeOwnershipHandoverDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, KEYS_HASH,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("saveWalletKeysHash matches Solidity", async () => {
    const newTransactionKeys = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      (_, i) => makeKey(BigInt(5000 + i * 2))
    );
    const newRecoveryKeys = Array.from(
      { length: RECOVERY_KEY_AMOUNT },
      (_, i) => makeKey(BigInt(6000 + i * 2))
    );
    const tsHash = saveWalletKeysHash(newTransactionKeys, newRecoveryKeys);
    const solHash = await callHarness("exposed_saveWalletKeysHash", [
      newTransactionKeys, newRecoveryKeys,
    ]);
    expect(tsHash).toBe(solHash);
  });

  test("ownershipTransferKeysHash matches Solidity", async () => {
    const newDisaster = makeKey(7777n);
    const newTransactionKeys = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      (_, i) => makeKey(BigInt(8000 + i * 2))
    );
    const newRecoveryKeys = Array.from(
      { length: RECOVERY_KEY_AMOUNT },
      (_, i) => makeKey(BigInt(9000 + i * 2))
    );
    const tsHash = ownershipTransferKeysHash(
      newDisaster,
      newTransactionKeys,
      newRecoveryKeys
    );
    const solHash = await callHarness("exposed_ownershipTransferKeysHash", [
      newDisaster, newTransactionKeys, newRecoveryKeys,
    ]);
    expect(tsHash).toBe(solHash);
  });
});

// ─── Roundtrip tests (pure TS) ───────────────────────────────────

function expectAddressEq(a: WinternitzAddress, b: WinternitzAddress) {
  expect(a.publicSeed).toBe(b.publicSeed);
  expect(a.publicKeyHash).toBe(b.publicKeyHash);
}

function expectElementsEq(a: WinternitzElements, b: WinternitzElements) {
  expect(a.elements.length).toBe(b.elements.length);
  for (let i = 0; i < a.elements.length; i++) {
    expect(a.elements[i]).toBe(b.elements[i]);
  }
}

describe("encode/decode roundtrip", () => {
  const cur = makeKey(1n);
  const next = makeKey(3n);
  const sig = makeSig(1n);

  test("init", () => {
    const disaster = makeKey(999n);
    const ownership = makeKey(1001n);
    const txnKeys = Array.from({ length: TRANSACTION_KEY_INIT_AMOUNT }, (_, i) =>
      makeKey(BigInt(2 + i * 2)),
    );
    const recoveryKeys = Array.from({ length: RECOVERY_KEY_AMOUNT }, (_, i) =>
      makeKey(BigInt(10 + i * 2)),
    );
    const encoded = encodeInit(disaster, ownership, txnKeys, recoveryKeys);
    expect(size(encoded)).toBe(1088);
    const decoded = decodeInit(encoded);
    expectAddressEq(decoded.disasterRecoveryKey, disaster);
    expectAddressEq(decoded.ownershipKey, ownership);
    expect(decoded.transactionKeys.length).toBe(TRANSACTION_KEY_INIT_AMOUNT);
    for (let i = 0; i < TRANSACTION_KEY_INIT_AMOUNT; i++) {
      expectAddressEq(decoded.transactionKeys[i], txnKeys[i]);
    }
    expect(decoded.recoveryKeys.length).toBe(RECOVERY_KEY_AMOUNT);
    for (let i = 0; i < RECOVERY_KEY_AMOUNT; i++) {
      expectAddressEq(decoded.recoveryKeys[i], recoveryKeys[i]);
    }
  });

  test("execute with data", () => {
    const data: Hex = "0xdeadbeef";
    const encoded = encodeExecute(cur, next, sig, TARGET, VALUE, data);
    const decoded = decodeExecute(encoded);
    expectAddressEq(decoded.currentKey, cur);
    expectAddressEq(decoded.nextKey, next);
    expectElementsEq(decoded.pqSig, sig);
    expect(getAddress(decoded.target)).toBe(getAddress(TARGET));
    expect(decoded.value).toBe(VALUE);
    expect(decoded.data).toBe(data);
  });

  test("execute without data (transfer)", () => {
    const encoded = encodeExecute(cur, next, sig, TARGET, VALUE);
    expect(size(encoded)).toBe(2336);
    const decoded = decodeExecute(encoded);
    expectAddressEq(decoded.currentKey, cur);
    expectAddressEq(decoded.nextKey, next);
    expect(getAddress(decoded.target)).toBe(getAddress(TARGET));
    expect(decoded.value).toBe(VALUE);
    expect(decoded.data).toBe("0x");
  });

  test("recoverWallet", () => {
    const recovery = makeKey(5n);
    const newRecovery = makeKey(7n);
    const newTransaction = makeKey(9n);
    const encoded = encodeRecoverWallet(recovery, newRecovery, newTransaction, sig);
    expect(size(encoded)).toBe(2336);
    const decoded = decodeRecoverWallet(encoded);
    expectAddressEq(decoded.recoveryKey, recovery);
    expectAddressEq(decoded.newRecoveryKey, newRecovery);
    expectAddressEq(decoded.newTransactionKey, newTransaction);
    expectElementsEq(decoded.pqSig, sig);
  });

  test("keyManagement with multiple keys", () => {
    const keys = [makeKey(200n), makeKey(202n), makeKey(204n)];
    const encoded = encodeKeyManagement(KeyType.Recovery, cur, next, sig, keys);
    expect(size(encoded)).toBe(2304 + 3 * 64);
    const decoded = decodeKeyManagement(encoded);
    expect(decoded.kind).toBe(KeyType.Recovery);
    expectAddressEq(decoded.currentKey, cur);
    expectAddressEq(decoded.nextKey, next);
    expectElementsEq(decoded.pqSig, sig);
    expect(decoded.keys.length).toBe(3);
    for (let i = 0; i < 3; i++) {
      expectAddressEq(decoded.keys[i], keys[i]);
    }
  });

  test("keyManagement with zero keys", () => {
    const encoded = encodeKeyManagement(KeyType.Verification, cur, next, sig, []);
    expect(size(encoded)).toBe(2304);
    const decoded = decodeKeyManagement(encoded);
    expect(decoded.kind).toBe(KeyType.Verification);
    expect(decoded.keys.length).toBe(0);
  });

  test("withdrawDeposit", () => {
    const TO: Address = "0x000000000000000000000000000000000000beef";
    const AMOUNT = 42n * 10n ** 18n;
    const encoded = encodeWithdrawDeposit(cur, next, sig, TO, AMOUNT);
    expect(size(encoded)).toBe(2336);
    const decoded = decodeWithdrawDeposit(encoded);
    expectAddressEq(decoded.currentKey, cur);
    expectAddressEq(decoded.nextKey, next);
    expectElementsEq(decoded.pqSig, sig);
    expect(getAddress(decoded.to)).toBe(getAddress(TO));
    expect(decoded.amount).toBe(AMOUNT);
  });

  test("replaceKeyAt", () => {
    const newKey = makeKey(42n);
    const encoded = encodeReplaceKeyAt(KeyType.Recovery, cur, next, sig, 3n, newKey);
    expect(size(encoded)).toBe(2400);
    const decoded = decodeReplaceKeyAt(encoded);
    expect(decoded.kind).toBe(KeyType.Recovery);
    expectAddressEq(decoded.currentKey, cur);
    expectAddressEq(decoded.nextKey, next);
    expectElementsEq(decoded.pqSig, sig);
    expect(decoded.index).toBe(3n);
    expectAddressEq(decoded.newKey, newKey);
  });

  test("userOpSignature", () => {
    const encoded = encodeUserOpSignature(cur, next, sig);
    expect(size(encoded)).toBe(2272);
    const decoded = decodeUserOpSignature(encoded);
    expectAddressEq(decoded.currentKey, cur);
    expectAddressEq(decoded.nextKey, next);
    expectElementsEq(decoded.pqSig, sig);
  });

  test("saveWallet", () => {
    const currentDisaster = makeKey(900n);
    const newDisaster = makeKey(902n);
    const newTransactionKeys = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      (_, i) => makeKey(BigInt(1000 + i * 2))
    );
    const newRecoveryKeys = Array.from(
      { length: RECOVERY_KEY_AMOUNT },
      (_, i) => makeKey(BigInt(2000 + i * 2))
    );
    const encoded = encodeSaveWallet(
      currentDisaster,
      newDisaster,
      sig,
      newTransactionKeys,
      newRecoveryKeys
    );
    expect(size(encoded)).toBe(SAVE_WALLET_PAYLOAD_SIZE);
    const decoded = decodeSaveWallet(encoded);
    expectAddressEq(decoded.currentDisasterKey, currentDisaster);
    expectAddressEq(decoded.newDisasterKey, newDisaster);
    expectElementsEq(decoded.pqSig, sig);
    expect(decoded.newTransactionKeys.length).toBe(TRANSACTION_KEY_INIT_AMOUNT);
    for (let i = 0; i < TRANSACTION_KEY_INIT_AMOUNT; i++) {
      expectAddressEq(decoded.newTransactionKeys[i], newTransactionKeys[i]);
    }
    expect(decoded.newRecoveryKeys.length).toBe(RECOVERY_KEY_AMOUNT);
    for (let i = 0; i < RECOVERY_KEY_AMOUNT; i++) {
      expectAddressEq(decoded.newRecoveryKeys[i], newRecoveryKeys[i]);
    }
  });

  test("ownershipTransfer", () => {
    const currentOwnership = makeKey(800n);
    const newOwnership = makeKey(802n);
    const newDisaster = makeKey(804n);
    const newTransactionKeys = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      (_, i) => makeKey(BigInt(3000 + i * 2))
    );
    const newRecoveryKeys = Array.from(
      { length: RECOVERY_KEY_AMOUNT },
      (_, i) => makeKey(BigInt(4000 + i * 2))
    );
    const encoded = encodeOwnershipTransfer(
      currentOwnership,
      newOwnership,
      sig,
      TARGET,
      newDisaster,
      newTransactionKeys,
      newRecoveryKeys
    );
    expect(size(encoded)).toBe(OWNERSHIP_TRANSFER_PAYLOAD_SIZE);
    const decoded = decodeOwnershipTransfer(encoded);
    expectAddressEq(decoded.currentOwnershipKey, currentOwnership);
    expectAddressEq(decoded.newOwnershipKey, newOwnership);
    expectElementsEq(decoded.pqSig, sig);
    expect(getAddress(decoded.newOwner)).toBe(getAddress(TARGET));
    expectAddressEq(decoded.newDisasterKey, newDisaster);
    for (let i = 0; i < TRANSACTION_KEY_INIT_AMOUNT; i++) {
      expectAddressEq(decoded.newTransactionKeys[i], newTransactionKeys[i]);
    }
    for (let i = 0; i < RECOVERY_KEY_AMOUNT; i++) {
      expectAddressEq(decoded.newRecoveryKeys[i], newRecoveryKeys[i]);
    }
  });

  test("upgradeToAndCall without migrate", () => {
    const verifier = makeKey(600n);
    const verifySig = makeSig(600n);
    const encoded = encodeUpgradeToAndCall(
      cur,
      next,
      sig,
      verifier,
      verifySig,
      false,
      "0x"
    );
    expect(size(encoded)).toBe(UPGRADE_PAYLOAD_SIZE);
    const decoded = decodeUpgradeToAndCall(encoded);
    expectAddressEq(decoded.currentKey, cur);
    expectAddressEq(decoded.nextKey, next);
    expectElementsEq(decoded.pqSig, sig);
    expectAddressEq(decoded.verifier, verifier);
    expectElementsEq(decoded.verifySig, verifySig);
    expect(decoded.shouldMigrate).toBe(false);
    expect(size(decoded.migratorPayload)).toBe(1088);
  });

  test("upgradeToAndCall with migrate", () => {
    const verifier = makeKey(700n);
    const verifySig = makeSig(700n);
    const initDisaster = makeKey(8000n);
    const initOwnership = makeKey(8002n);
    const initTxn = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      (_, i) => makeKey(BigInt(8100 + i * 2))
    );
    const initRecovery = Array.from(
      { length: RECOVERY_KEY_AMOUNT },
      (_, i) => makeKey(BigInt(8200 + i * 2))
    );
    const migrator = encodeInit(initDisaster, initOwnership, initTxn, initRecovery);
    const encoded = encodeUpgradeToAndCall(
      cur,
      next,
      sig,
      verifier,
      verifySig,
      true,
      migrator
    );
    expect(size(encoded)).toBe(UPGRADE_PAYLOAD_SIZE);
    const decoded = decodeUpgradeToAndCall(encoded);
    expect(decoded.shouldMigrate).toBe(true);
    expect(decoded.migratorPayload).toBe(migrator);
  });

  test("recoveryUpgrade", () => {
    const verifier = makeKey(500n);
    const verifySig = makeSig(500n);
    const encoded = encodeRecoveryUpgrade(cur, next, sig, verifier, verifySig);
    expect(size(encoded)).toBe(RECOVERY_UPGRADE_PAYLOAD_SIZE);
    const decoded = decodeRecoveryUpgrade(encoded);
    expectAddressEq(decoded.currentRecoveryKey, cur);
    expectAddressEq(decoded.newRecoveryKey, next);
    expectElementsEq(decoded.pqSig, sig);
    expectAddressEq(decoded.verifier, verifier);
    expectElementsEq(decoded.verifySig, verifySig);
  });
});
