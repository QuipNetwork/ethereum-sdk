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
  encodeInit,
  encodeChangePqOwner,
  encodeExecute,
  encodeRecoverWallet,
  encodeKeyManagement,
  encodeUpgrade,
  encodeRecoveryUpgradeData,
  decodeInit,
  decodeUpgradeAuth,
  decodeUpgradeVerification,
  decodeUpgradeMigration,
  decodeChangePqOwner,
  decodeExecute,
  decodeRecoverWallet,
  decodeKeyManagement,
  decodeRecoveryUpgradeData,
  keyRotationDigest,
  executeDigest,
  keyManagementDigest,
  upgradeDigest,
  verificationDigest,
  upgradeRecoveryDigest,
  RECOVERY_KEY_AMOUNT,
} from "./wotsCodec.js";

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
const TARGET: Address = "0x0000000000000000000000000000000000000002";
const IMPL: Address = "0x0000000000000000000000000000000000000003";
const VALUE = 1000n;
const OPDATA_HASH: Hex = toHex(99n, { size: 32 });
const KEYS_HASH: Hex = toHex(88n, { size: 32 });

// ─── Encoder parity tests (live Solidity comparison) ─────────────

describe("encoder parity (live Solidity)", () => {
  const pq = makeKey(1n);
  const sig = makeSig(1n);

  test("encodeChangePqOwner matches Solidity", async () => {
    const tsEncoded = encodeChangePqOwner(pq, sig);
    const solEncoded = await callHarness("exposed_encodeChangePqOwner", [pq, sig]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeRecoverWallet matches Solidity", async () => {
    const recoveryKey = makeKey(1n);
    const newPqOwner = makeKey(3n);
    const tsEncoded = encodeRecoverWallet(recoveryKey, newPqOwner, sig);
    const solEncoded = await callHarness("exposed_encodeRecoverWallet", [
      recoveryKey,
      newPqOwner,
      sig,
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeExecute matches Solidity", async () => {
    const tsEncoded = encodeExecute(pq, sig, TARGET, VALUE, "0xdeadbeef");
    const solEncoded = await callHarness("exposed_encodeExecute", [
      pq,
      sig,
      TARGET,
      VALUE,
      "0xdeadbeef",
    ]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeKeyManagement matches Solidity", async () => {
    const keys: WinternitzAddress[] = [makeKey(200n), makeKey(202n)];
    const tsEncoded = encodeKeyManagement(pq, sig, keys);
    const solEncoded = await callHarness("exposed_encodeKeyManagement", [pq, sig, keys]);
    expect(tsEncoded).toBe(solEncoded);
  });

  test("encodeRecoveryUpgradeData matches Solidity", async () => {
    const recoveryKey = makeKey(1n);
    const tsEncoded = encodeRecoveryUpgradeData(recoveryKey, sig);
    const solEncoded = await callHarness("exposed_encodeRecoveryUpgradeData", [recoveryKey, sig]);
    expect(tsEncoded).toBe(solEncoded);
  });
});

// ─── Digest parity tests (live Solidity comparison) ──────────────

describe("digest parity (live Solidity)", () => {
  test("keyRotationDigest matches Solidity", async () => {
    const tsDigest = keyRotationDigest(WALLET, CHAIN_ID, S1, H1, S2, H2);
    const solDigest = await callHarness("exposed_keyRotationDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("executeDigest matches Solidity", async () => {
    const tsDigest = executeDigest(
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, VALUE, OPDATA_HASH,
    );
    const solDigest = await callHarness("exposed_executeDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2, TARGET, VALUE, OPDATA_HASH,
    ]);
    expect(tsDigest).toBe(solDigest);
  });

  test("keyManagementDigest matches Solidity", async () => {
    const tsDigest = keyManagementDigest(WALLET, CHAIN_ID, S1, H1, S2, H2, KEYS_HASH);
    const solDigest = await callHarness("exposed_keyManagementDigest", [
      WALLET, CHAIN_ID, S1, H1, S2, H2, KEYS_HASH,
    ]);
    expect(tsDigest).toBe(solDigest);
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
  const pq = makeKey(1n);
  const sig = makeSig(1n);

  test("init", () => {
    const keys = Array.from({ length: RECOVERY_KEY_AMOUNT }, (_, i) =>
      makeKey(BigInt(10 + i * 2)),
    );
    const encoded = encodeInit(pq, keys);
    expect(size(encoded)).toBe(704);
    const decoded = decodeInit(encoded);
    expectAddressEq(decoded.pqOwner, pq);
    expect(decoded.recoveryKeys.length).toBe(RECOVERY_KEY_AMOUNT);
    for (let i = 0; i < RECOVERY_KEY_AMOUNT; i++) {
      expectAddressEq(decoded.recoveryKeys[i], keys[i]);
    }
  });

  test("changePqOwner", () => {
    const encoded = encodeChangePqOwner(pq, sig);
    const decoded = decodeChangePqOwner(encoded);
    expectAddressEq(decoded.newPqOwner, pq);
    expectElementsEq(decoded.pqSig, sig);
  });

  test("execute with data", () => {
    const data: Hex = "0xdeadbeef";
    const encoded = encodeExecute(pq, sig, TARGET, VALUE, data);
    const decoded = decodeExecute(encoded);
    expectAddressEq(decoded.nextPqOwner, pq);
    expectElementsEq(decoded.pqSig, sig);
    expect(getAddress(decoded.target)).toBe(getAddress(TARGET));
    expect(decoded.value).toBe(VALUE);
    expect(decoded.data).toBe(data);
  });

  test("execute without data (transfer)", () => {
    const encoded = encodeExecute(pq, sig, TARGET, VALUE);
    expect(size(encoded)).toBe(2272);
    const decoded = decodeExecute(encoded);
    expect(getAddress(decoded.target)).toBe(getAddress(TARGET));
    expect(decoded.value).toBe(VALUE);
    expect(decoded.data).toBe("0x");
  });

  test("recoverWallet", () => {
    const recoveryKey = makeKey(3n);
    const encoded = encodeRecoverWallet(recoveryKey, pq, sig);
    expect(size(encoded)).toBe(2272);
    const decoded = decodeRecoverWallet(encoded);
    expectAddressEq(decoded.recoveryKey, recoveryKey);
    expectAddressEq(decoded.newPqOwner, pq);
    expectElementsEq(decoded.pqSig, sig);
  });

  test("recoveryUpgradeData", () => {
    const recoveryKey = makeKey(3n);
    const encoded = encodeRecoveryUpgradeData(recoveryKey, sig);
    expect(size(encoded)).toBe(2208);
    const decoded = decodeRecoveryUpgradeData(encoded);
    expectAddressEq(decoded.recoveryKey, recoveryKey);
    expectElementsEq(decoded.pqSig, sig);
  });

  test("keyManagement with multiple keys", () => {
    const keys = [makeKey(200n), makeKey(202n), makeKey(204n)];
    const encoded = encodeKeyManagement(pq, sig, keys);
    expect(size(encoded)).toBe(2208 + 3 * 64);
    const decoded = decodeKeyManagement(encoded);
    expectAddressEq(decoded.nextPqOwner, pq);
    expectElementsEq(decoded.pqSig, sig);
    expect(decoded.newRecoveryKeys.length).toBe(3);
    for (let i = 0; i < 3; i++) {
      expectAddressEq(decoded.newRecoveryKeys[i], keys[i]);
    }
  });

  test("keyManagement with zero keys", () => {
    const encoded = encodeKeyManagement(pq, sig, []);
    expect(size(encoded)).toBe(2208);
    const decoded = decodeKeyManagement(encoded);
    expect(decoded.newRecoveryKeys.length).toBe(0);
  });

  test("upgrade", () => {
    const verifier = makeKey(5n);
    const verifySig = makeSig(5n);
    const initKeys = Array.from({ length: RECOVERY_KEY_AMOUNT }, (_, i) =>
      makeKey(BigInt(20 + i * 2)),
    );
    const migratorPayload = encodeInit(makeKey(50n), initKeys);

    const encoded = encodeUpgrade(pq, sig, verifier, verifySig, true, migratorPayload);
    expect(size(encoded)).toBe(5121);

    const auth = decodeUpgradeAuth(encoded);
    expectAddressEq(auth.nextPqOwner, pq);
    expectElementsEq(auth.pqSig, sig);

    const ver = decodeUpgradeVerification(encoded);
    expectAddressEq(ver.verifier, verifier);
    expectElementsEq(ver.verifySig, verifySig);

    const mig = decodeUpgradeMigration(encoded);
    expect(mig.shouldMigrate).toBe(true);
    expect(size(mig.migratorPayload)).toBe(704);
  });

  test("upgrade with shouldMigrate=false", () => {
    const verifier = makeKey(5n);
    const verifySig = makeSig(5n);
    const migratorPayload = ("0x" + "00".repeat(704)) as Hex;

    const encoded = encodeUpgrade(pq, sig, verifier, verifySig, false, migratorPayload);
    const mig = decodeUpgradeMigration(encoded);
    expect(mig.shouldMigrate).toBe(false);
  });
});
