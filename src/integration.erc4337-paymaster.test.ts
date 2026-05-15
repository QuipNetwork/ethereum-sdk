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
  type TestClient,
  concat,
  createPublicClient,
  createWalletClient,
  createTestClient,
  encodeFunctionData,
  http,
  toHex,
  zeroAddress,
  parseEventLogs,
  parseEther,
} from "viem";
import { createAnvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { quipFactoryAbi } from "./abi/QuipFactory.js";
import { quipPaymasterAbi } from "./abi/QuipPaymaster.js";
import { entryPointV07Abi } from "./abi/EntryPointV07.js";
import { CANONICAL_ENTRYPOINT_V07 } from "./addresses.js";
import { QuipSigner } from "./signer.js";
import { createInMemoryBurnSet } from "./burnSet.js";
import { QuipWalletClient } from "./walletClient.js";
import { QuipPaymasterClient } from "./paymasterClient.js";
import { PaymasterValidationFailure } from "./errors.js";
import {
  encodeInit,
  type WinternitzAddress,
  TRANSACTION_KEY_INIT_AMOUNT,
  RECOVERY_KEY_AMOUNT,
} from "./wotsCodec.js";

// ─── Artifacts ──────────────────────────────────────────────────────
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

const paymasterArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/QuipPaymaster.sol/QuipPaymaster.json"),
    "utf8"
  )
);
const paymasterUnlinkedBytecode = paymasterArtifact.bytecode.object as string;
const quipPaymasterDeployAbi = paymasterArtifact.abi;

const wotsPlusArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/WOTSPlus.sol/WOTSPlus.json"),
    "utf8"
  )
);
const wotsPlusBytecode = wotsPlusArtifact.bytecode.object as Hex;
const wotsPlusAbi = wotsPlusArtifact.abi;

const entryPointFixture = JSON.parse(
  readFileSync(
    join(process.cwd(), "src/fixtures/entrypoint-v0.7.json"),
    "utf8"
  )
);
const entryPointDeployedBytecode = entryPointFixture.deployedBytecode as Hex;

function linkBytecode(unlinked: string, linkRefs: Record<
  string,
  Record<string, Array<{ start: number; length: number }>>
>, libAddress: Address): Hex {
  let hex = unlinked.replace(/^0x/, "");
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

const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(ANVIL_PRIV_KEY);

const anvil = createAnvil({ port: 8553 });
let publicClient: PublicClient;
let walletClient: WalletClient;
let testClient: TestClient;
let factoryAddress: Address;
let paymasterAddress: Address;

const MAX_FEE = 10n ** 16n;

function buildInitPayload(signer: QuipSigner, vaultId: Hex): Hex {
  const disaster = signer.generateKeyPair(vaultId).publicKey;
  const ownership = signer.generateKeyPair(vaultId).publicKey;
  const transactionKeys = Array.from(
    { length: TRANSACTION_KEY_INIT_AMOUNT },
    () => signer.generateKeyPair(vaultId).publicKey
  );
  const recoveryKeys = Array.from({ length: RECOVERY_KEY_AMOUNT }, () =>
    signer.generateKeyPair(vaultId).publicKey
  );
  return encodeInit(disaster, ownership, transactionKeys, recoveryKeys);
}

async function createFreshWallet(seedByte: number): Promise<{
  signer: QuipSigner;
  vaultId: Hex;
  client: QuipWalletClient;
  walletAddress: Address;
}> {
  const quantumSecret = new Uint8Array(32).fill(seedByte);
  const signer = new QuipSigner(quantumSecret, createInMemoryBurnSet().consume);
  const vaultId = toHex(new Uint8Array(32).fill(seedByte));
  const initPayload = buildInitPayload(signer, vaultId);
  const hash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "deployLatestWalletProxy",
    args: [vaultId, account.address, initPayload],
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  const logs = parseEventLogs({
    abi: quipFactoryAbi,
    logs: receipt.logs,
    eventName: "QuipCreated",
  });
  const walletAddress = logs[0].args.quip;
  await testClient.setBalance({
    address: walletAddress,
    value: parseEther("1"),
  });
  const client = new QuipWalletClient(
    signer,
    vaultId,
    walletAddress,
    publicClient,
    walletClient,
    account.address,
    foundry.id
  );
  return { signer, vaultId, client, walletAddress };
}

/// Deploy a Solady minimal ERC-1967 proxy pointing at `impl`. Mirrors the
/// initcode used by `QuipFactory._deployProxy`.
async function deployErc1967Proxy(impl: Address): Promise<Address> {
  const initcode = concat([
    "0x603d3d8160223d3973",
    impl,
    "0x6009",
    "0x5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076",
    "0xcc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3",
  ]);
  const hash = await walletClient.sendTransaction({
    chain: foundry,
    data: initcode,
    account,
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  return receipt.contractAddress!;
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

  // 1. EntryPoint v0.7 at canonical address.
  await testClient.setCode({
    address: CANONICAL_ENTRYPOINT_V07,
    bytecode: entryPointDeployedBytecode,
  });

  // 2. QuipFactory.
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

  // 3. WOTSPlus library.
  const wotsHash = await walletClient.deployContract({
    abi: wotsPlusAbi,
    bytecode: wotsPlusBytecode,
    account,
    chain: foundry,
  });
  const wotsReceipt = await publicClient.waitForTransactionReceipt({
    hash: wotsHash,
  });
  const wotsAddr = wotsReceipt.contractAddress!;

  // 4. QuipWallet impl + vet.
  const walletBytecode = linkBytecode(
    walletUnlinkedBytecode,
    walletArtifact.bytecode.linkReferences,
    wotsAddr
  );
  const walletImplHash = await walletClient.deployContract({
    abi: quipWalletDeployAbi,
    bytecode: walletBytecode,
    args: [factoryAddress],
    account,
    chain: foundry,
  });
  const walletImplReceipt = await publicClient.waitForTransactionReceipt({
    hash: walletImplHash,
  });
  const vetHash = await walletClient.writeContract({
    chain: foundry,
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "vetImplementation",
    args: [walletImplReceipt.contractAddress!],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: vetHash });

  // 5. QuipPaymaster: impl + ERC-1967 proxy + initialize + deposit.
  const paymasterBytecode = linkBytecode(
    paymasterUnlinkedBytecode,
    paymasterArtifact.bytecode.linkReferences,
    wotsAddr
  );
  const pmImplHash = await walletClient.deployContract({
    abi: quipPaymasterDeployAbi,
    bytecode: paymasterBytecode,
    account,
    chain: foundry,
  });
  const pmImplReceipt = await publicClient.waitForTransactionReceipt({
    hash: pmImplHash,
  });
  paymasterAddress = await deployErc1967Proxy(pmImplReceipt.contractAddress!);
  const initHash = await walletClient.writeContract({
    chain: foundry,
    address: paymasterAddress,
    abi: quipPaymasterAbi,
    functionName: "initialize",
    args: [account.address],
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: initHash });

  // Pre-deposit 1 ETH so the paymaster can sponsor.
  const depHash = await walletClient.writeContract({
    chain: foundry,
    address: paymasterAddress,
    abi: quipPaymasterAbi,
    functionName: "deposit",
    args: [],
    value: parseEther("1"),
    account,
  });
  await publicClient.waitForTransactionReceipt({ hash: depHash });
}, 120_000);

afterAll(async () => {
  await anvil.stop().catch(() => {});
}, 10_000);

// ─── Tests ──────────────────────────────────────────────────────────

describe("QuipPaymasterClient reads + admin writes", () => {
  test("getDeposit / owner / getPqVerifier(zero) on a freshly initialized paymaster", async () => {
    const pmClient = new QuipPaymasterClient({
      paymasterAddress,
      publicClient,
      walletClient,
      account: account.address,
      chainId: foundry.id,
    });
    expect(await pmClient.owner()).toBe(account.address);
    expect(await pmClient.getDeposit()).toBeGreaterThanOrEqual(parseEther("1"));
    const verifier = await pmClient.getPqVerifier(
      "0x0000000000000000000000000000000000000123"
    );
    expect(verifier.publicSeed).toBe(
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
  });

  test("setPqVerifier registers a verifier for a wallet", async () => {
    const pmClient = new QuipPaymasterClient({
      paymasterAddress,
      publicClient,
      walletClient,
      account: account.address,
      chainId: foundry.id,
    });
    const operator = new QuipSigner(new Uint8Array(32).fill(0x10), createInMemoryBurnSet().consume);
    const vaultId = toHex(new Uint8Array(32).fill(0x10));
    const verifierKey = operator.generateKeyPair(vaultId).publicKey;
    const fakeWallet = "0x0000000000000000000000000000000000005a01" as Address;
    await pmClient.setPqVerifier(fakeWallet, verifierKey);
    const read = await pmClient.getPqVerifier(fakeWallet);
    expect(read.publicSeed).toBe(verifierKey.publicSeed);
    expect(read.publicKeyHash).toBe(verifierKey.publicKeyHash);
  }, 30_000);
});

describe("Sponsored UserOp end-to-end", () => {
  test("happy path: build wallet UserOp → sponsor → handleOps → UserOpSponsored emitted", async () => {
    const { client: walletSdk, walletAddress } = await createFreshWallet(0x50);
    const pmClient = new QuipPaymasterClient({
      paymasterAddress,
      publicClient,
      walletClient,
      account: account.address,
      chainId: foundry.id,
    });

    // Operator signer for the paymaster's per-wallet verifier chain.
    const operator = new QuipSigner(new Uint8Array(32).fill(0x51), createInMemoryBurnSet().consume);
    const operatorVault = toHex(new Uint8Array(32).fill(0x51));
    const currentVerifier = operator.generateKeyPair(operatorVault).publicKey;

    // Register the verifier as the head of `walletAddress`'s chain.
    await pmClient.setPqVerifier(walletAddress, currentVerifier);

    // 1. PREPARE the unsigned wallet UserOp (no wallet sig yet).
    const prepared = await walletSdk.prepareExecuteUserOp(
      zeroAddress,
      0n,
      "0x"
    );

    // 2. PAYMASTER SPONSORSHIP — operator signs paymaster digest over
    //    constituent fields and fills `paymasterAndData`. Wallet sig is
    //    still "0x".
    const sponsored = await pmClient.sponsorUserOp({
      userOp: prepared.userOp,
      operatorSigner: operator,
      vaultId: operatorVault,
      currentVerifier: {
        publicSeed: currentVerifier.publicSeed,
        publicKeyHash: currentVerifier.publicKeyHash,
      },
    });
    expect(sponsored.userOp.paymasterAndData).not.toBe("0x");

    // 3. WALLET SIGN — over the FINAL userOpHash that now includes
    //    paymasterAndData. signExecuteUserOp reuses the keys picked
    //    during prepare.
    const final = await walletSdk.signExecuteUserOp({
      ...prepared,
      userOp: sponsored.userOp,
    });

    // 4. Simulate both sides — should both be 'ok'.
    const sim = await walletSdk.simulateUserOp(final.userOp);
    expect(sim.walletValidation).toBe("ok");
    expect(sim.paymasterValidation).toBe("ok");
    expect(sim.keysBurnedIfRevert).toEqual({ wallet: true, paymaster: true });

    // 5. Submit via handleOps. Both keys (wallet + verifier) were burned
    //    at sign time; the on-chain rotation will commit during
    //    validation.
    const handleHash = await walletClient.writeContract({
      chain: foundry,
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "handleOps",
      args: [[final.userOp], account.address],
      account,
      gas: 3_000_000n,
    });
    const receipt = await publicClient.waitForTransactionReceipt({
      hash: handleHash,
    });

    // 5. UserOpSponsored emitted by the paymaster.
    const sponsoredEvents = parseEventLogs({
      abi: quipPaymasterAbi,
      logs: receipt.logs,
      eventName: "UserOpSponsored",
    });
    expect(sponsoredEvents.length).toBe(1);
    expect(sponsoredEvents[0].args.wallet).toBe(walletAddress);

    // EntryPoint's UserOperationEvent should report success.
    const opEvents = parseEventLogs({
      abi: entryPointV07Abi,
      logs: receipt.logs,
      eventName: "UserOperationEvent",
    });
    expect(opEvents.length).toBe(1);
    expect(opEvents[0].args.success).toBe(true);
    expect(opEvents[0].args.paymaster.toLowerCase()).toBe(
      paymasterAddress.toLowerCase()
    );

    // 6. Paymaster verifier rotated: getPqVerifier should now return
    //    `nextVerifier` (not the original `currentVerifier`).
    const verifierAfter = await pmClient.getPqVerifier(walletAddress);
    expect(verifierAfter.publicSeed).toBe(sponsored.nextVerifier.publicSeed);
    expect(verifierAfter.publicSeed).not.toBe(
      currentVerifier.publicSeed
    );
  }, 90_000);
});

describe("simulateUserOp — paymaster rejection paths", () => {
  test("NoVerifierRegistered: paymaster has no verifier for sender", async () => {
    const { client: walletSdk, walletAddress } = await createFreshWallet(0x60);
    const operator = new QuipSigner(new Uint8Array(32).fill(0x61), createInMemoryBurnSet().consume);
    const operatorVault = toHex(new Uint8Array(32).fill(0x61));
    const verifier = operator.generateKeyPair(operatorVault).publicKey;

    const pmClient = new QuipPaymasterClient({
      paymasterAddress,
      publicClient,
      walletClient,
      account: account.address,
      chainId: foundry.id,
    });

    // DO NOT register a verifier for this wallet.
    const prepared = await walletSdk.prepareExecuteUserOp(
      zeroAddress,
      0n,
      "0x"
    );
    // sponsorUserOp would normally pull current verifier from chain. We
    // pass a fabricated currentVerifier — the paymaster's pre-flight read
    // sees zero on-chain and rejects with NoVerifierRegistered. Pretend
    // the operator believes it has a verifier registered.
    const fabricated = {
      publicSeed: verifier.publicSeed,
      publicKeyHash: verifier.publicKeyHash,
    };
    const sponsored = await pmClient.sponsorUserOp({
      userOp: prepared.userOp,
      operatorSigner: operator,
      vaultId: operatorVault,
      currentVerifier: fabricated,
    });
    void walletAddress;

    const sim = await walletSdk.simulateUserOp(sponsored.userOp);
    expect(sim.paymasterValidation).toBe(
      PaymasterValidationFailure.NoVerifierRegistered
    );
    expect(sim.keysBurnedIfRevert.paymaster).toBe(false);
  }, 60_000);

  test("ZeroNextVerifier: paymasterAndData has zero nextVerifier", async () => {
    const { client: walletSdk, walletAddress } = await createFreshWallet(0x62);
    const operator = new QuipSigner(new Uint8Array(32).fill(0x63), createInMemoryBurnSet().consume);
    const operatorVault = toHex(new Uint8Array(32).fill(0x63));
    const currentVerifier = operator.generateKeyPair(operatorVault).publicKey;
    const pmClient = new QuipPaymasterClient({
      paymasterAddress,
      publicClient,
      walletClient,
      account: account.address,
      chainId: foundry.id,
    });
    await pmClient.setPqVerifier(walletAddress, currentVerifier);

    const prepared = await walletSdk.prepareExecuteUserOp(
      zeroAddress,
      0n,
      "0x"
    );
    const sponsored = await pmClient.sponsorUserOp({
      userOp: prepared.userOp,
      operatorSigner: operator,
      vaultId: operatorVault,
      currentVerifier: {
        publicSeed: currentVerifier.publicSeed,
        publicKeyHash: currentVerifier.publicKeyHash,
      },
    });

    // Surgically zero the nextVerifier region in paymasterAndData.
    // Layout: [0:20) paymaster, [20:36) validationGas, [36:52) postOpGas,
    //         [52:58) validUntil, [58:64) validAfter, [64:128) nextVerifier,
    //         [128:2272) sig.
    // Zero bytes [64:128) — chars [128:256) of the hex string.
    const pmd = sponsored.userOp.paymasterAndData.slice(2);
    const tampered =
      "0x" + pmd.slice(0, 64 * 2) + "00".repeat(64) + pmd.slice(128 * 2);
    const malformed = {
      ...sponsored.userOp,
      paymasterAndData: tampered as Hex,
    };
    const sim = await walletSdk.simulateUserOp(malformed);
    expect(sim.paymasterValidation).toBe(
      PaymasterValidationFailure.ZeroNextVerifier
    );
  }, 60_000);

  test("NextEqualsCurrent: nextVerifier matches the registered currentVerifier", async () => {
    const { client: walletSdk, walletAddress } = await createFreshWallet(0x64);
    const operator = new QuipSigner(new Uint8Array(32).fill(0x65), createInMemoryBurnSet().consume);
    const operatorVault = toHex(new Uint8Array(32).fill(0x65));
    const currentVerifier = operator.generateKeyPair(operatorVault).publicKey;
    const pmClient = new QuipPaymasterClient({
      paymasterAddress,
      publicClient,
      walletClient,
      account: account.address,
      chainId: foundry.id,
    });
    await pmClient.setPqVerifier(walletAddress, currentVerifier);

    const prepared = await walletSdk.prepareExecuteUserOp(
      zeroAddress,
      0n,
      "0x"
    );
    // Sponsor but with nextVerifier === currentVerifier (force via param).
    const sponsored = await pmClient.sponsorUserOp({
      userOp: prepared.userOp,
      operatorSigner: operator,
      vaultId: operatorVault,
      currentVerifier: {
        publicSeed: currentVerifier.publicSeed,
        publicKeyHash: currentVerifier.publicKeyHash,
      },
      nextVerifier: currentVerifier,
    });

    const sim = await walletSdk.simulateUserOp(sponsored.userOp);
    expect(sim.paymasterValidation).toBe(
      PaymasterValidationFailure.NextEqualsCurrent
    );
  }, 60_000);

  test("NextVerifierKeyInUse: nextVerifier is already registered for another wallet", async () => {
    const { client: walletSdkA, walletAddress: walletA } =
      await createFreshWallet(0x66);
    const { client: walletSdkB, walletAddress: walletB } =
      await createFreshWallet(0x67);

    const operator = new QuipSigner(new Uint8Array(32).fill(0x68), createInMemoryBurnSet().consume);
    const operatorVault = toHex(new Uint8Array(32).fill(0x68));
    const verifierA = operator.generateKeyPair(operatorVault).publicKey;
    const verifierB_current =
      operator.generateKeyPair(operatorVault).publicKey;

    const pmClient = new QuipPaymasterClient({
      paymasterAddress,
      publicClient,
      walletClient,
      account: account.address,
      chainId: foundry.id,
    });
    // Register verifierA on walletA → this marks it used in the monotonic
    // index.
    await pmClient.setPqVerifier(walletA, verifierA);
    await pmClient.setPqVerifier(walletB, verifierB_current);

    // Sponsor walletB's UserOp but try to pivot to verifierA as next —
    // should be rejected by the in-use check.
    const prepared = await walletSdkB.prepareExecuteUserOp(
      zeroAddress,
      0n,
      "0x"
    );
    const sponsored = await pmClient.sponsorUserOp({
      userOp: prepared.userOp,
      operatorSigner: operator,
      vaultId: operatorVault,
      currentVerifier: {
        publicSeed: verifierB_current.publicSeed,
        publicKeyHash: verifierB_current.publicKeyHash,
      },
      nextVerifier: verifierA,
    });

    const sim = await walletSdkB.simulateUserOp(sponsored.userOp);
    expect(sim.paymasterValidation).toBe(
      PaymasterValidationFailure.NextVerifierKeyInUse
    );
    void walletSdkA;
  }, 60_000);

  test("InvalidSignature: WOTS+ sig elements tampered", async () => {
    const { client: walletSdk, walletAddress } = await createFreshWallet(0x69);
    const operator = new QuipSigner(new Uint8Array(32).fill(0x6a), createInMemoryBurnSet().consume);
    const operatorVault = toHex(new Uint8Array(32).fill(0x6a));
    const currentVerifier = operator.generateKeyPair(operatorVault).publicKey;
    const pmClient = new QuipPaymasterClient({
      paymasterAddress,
      publicClient,
      walletClient,
      account: account.address,
      chainId: foundry.id,
    });
    await pmClient.setPqVerifier(walletAddress, currentVerifier);

    const prepared = await walletSdk.prepareExecuteUserOp(
      zeroAddress,
      0n,
      "0x"
    );
    const sponsored = await pmClient.sponsorUserOp({
      userOp: prepared.userOp,
      operatorSigner: operator,
      vaultId: operatorVault,
      currentVerifier: {
        publicSeed: currentVerifier.publicSeed,
        publicKeyHash: currentVerifier.publicKeyHash,
      },
    });

    // Flip one byte deep inside the WOTS+ signature region.
    // Layout: [128:2272) sig.
    const pmd = sponsored.userOp.paymasterAndData.slice(2);
    const tamperOffset = 2 * 200; // somewhere in the sig
    const tampered =
      "0x" +
      pmd.slice(0, tamperOffset) +
      "ff" +
      pmd.slice(tamperOffset + 2);
    const malformed = {
      ...sponsored.userOp,
      paymasterAndData: tampered as Hex,
    };
    const sim = await walletSdk.simulateUserOp(malformed);
    expect(sim.paymasterValidation).toBe(
      PaymasterValidationFailure.InvalidSignature
    );
  }, 60_000);
});

describe("encodeFunctionData smoke for paymaster types", () => {
  test("setPqVerifier abi-encodes correctly", () => {
    const data = encodeFunctionData({
      abi: quipPaymasterAbi,
      functionName: "setPqVerifier",
      args: [
        zeroAddress,
        {
          publicSeed:
            "0x0000000000000000000000000000000000000000000000000000000000000001",
          publicKeyHash:
            "0x0000000000000000000000000000000000000000000000000000000000000002",
        },
      ],
    });
    expect(data.startsWith("0x")).toBe(true);
    expect(data.length).toBeGreaterThan(10);
  });
});
