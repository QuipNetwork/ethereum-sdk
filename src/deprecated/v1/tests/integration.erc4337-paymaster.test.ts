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
  encodeFunctionData,
  toHex,
  zeroAddress,
  parseEventLogs,
  parseEther,
} from "viem";
import { foundry } from "viem/chains";

import { quipPaymasterAbi } from "../../../v1/abi/QuipPaymaster.js";
import { entryPointV07Abi } from "../../../v1/abi/EntryPointV07.js";
import { CANONICAL_ENTRYPOINT_V07 } from "../../../v1/addresses.js";
import { QuipSigner } from "../signer.js";
import { createInMemoryBurnSet } from "../burnSet.js";
import { QuipPaymasterClient } from "../paymasterClient.js";
import {
  PaymasterValidationFailure,
  PqVerifierNotRegisteredError,
  VerifierMismatchError,
} from "../errors.js";
import { buildSignedPaymasterAndData } from "../userOp.js";
import { paymasterVerifierKeyUsedSlot } from "../wotsCodec.js";
import {
  ANVIL_PORTS,
  type AnvilStack,
  createFreshWallet,
  deployErc1967Proxy,
  linkBytecode,
  loadForgeArtifacts,
  setupAnvilStack,
  stopAnvilStack,
} from "./utils/anvilFixture.js";

let stack: AnvilStack;
let paymasterAddress: Address;

beforeAll(async () => {
  stack = await setupAnvilStack({ port: ANVIL_PORTS.erc4337Paymaster });

  // Deploy the QuipPaymaster: impl + ERC-1967 proxy + initialize + 1 ETH
  // deposit. The base stack already deployed WOTSPlus (the lib is shared
  // with the wallet impl), so we just link + deploy the paymaster impl.
  const artifacts = loadForgeArtifacts();
  const paymasterBytecode = linkBytecode(
    artifacts.paymasterUnlinkedBytecode,
    artifacts.paymasterArtifact.bytecode.linkReferences,
    stack.wotsPlusAddress
  );
  const pmImplHash = await stack.walletClient.deployContract({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    abi: artifacts.paymasterAbi as any,
    bytecode: paymasterBytecode,
    account: stack.account,
    chain: foundry,
  });
  const pmImplReceipt = await stack.publicClient.waitForTransactionReceipt({
    hash: pmImplHash,
  });
  paymasterAddress = await deployErc1967Proxy(
    stack.walletClient,
    stack.publicClient,
    stack.account,
    pmImplReceipt.contractAddress!
  );
  const initHash = await stack.walletClient.writeContract({
    chain: foundry,
    address: paymasterAddress,
    abi: quipPaymasterAbi,
    functionName: "initialize",
    args: [stack.account.address],
    account: stack.account,
  });
  await stack.publicClient.waitForTransactionReceipt({ hash: initHash });

  // Pre-deposit 1 ETH so the paymaster can sponsor.
  const depHash = await stack.walletClient.writeContract({
    chain: foundry,
    address: paymasterAddress,
    abi: quipPaymasterAbi,
    functionName: "deposit",
    args: [],
    value: parseEther("1"),
    account: stack.account,
  });
  await stack.publicClient.waitForTransactionReceipt({ hash: depHash });
}, 120_000);

afterAll(async () => {
  await stopAnvilStack(stack);
}, 10_000);

// Sugar: the paymaster file's wallets only need a funded balance; the
// paymaster covers prefund, so no EntryPoint deposit is needed.
async function freshWallet(seedByte: number) {
  return createFreshWallet(stack, seedByte, {
    walletBalance: parseEther("1"),
  });
}

function makePaymasterClient(): QuipPaymasterClient {
  return new QuipPaymasterClient({
    paymasterAddress,
    publicClient: stack.publicClient,
    walletClient: stack.walletClient,
    account: stack.account.address,
    chainId: foundry.id,
  });
}

// ─── Tests ──────────────────────────────────────────────────────────

describe("QuipPaymasterClient reads + admin writes", () => {
  test("getDeposit / owner / getPqVerifier(zero) on a freshly initialized paymaster", async () => {
    const pmClient = makePaymasterClient();
    expect(await pmClient.owner()).toBe(stack.account.address);
    expect(await pmClient.getDeposit()).toBeGreaterThanOrEqual(parseEther("1"));
    const verifier = await pmClient.getPqVerifier(
      "0x0000000000000000000000000000000000000123"
    );
    expect(verifier.publicSeed).toBe(
      "0x0000000000000000000000000000000000000000000000000000000000000000"
    );
  });

  test("setPqVerifier registers a verifier for a wallet", async () => {
    const pmClient = makePaymasterClient();
    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x10),
      createInMemoryBurnSet().consume
    );
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
    const { client: walletSdk, walletAddress } = await freshWallet(0x50);
    const pmClient = makePaymasterClient();

    // Operator signer for the paymaster's per-wallet verifier chain.
    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x51),
      createInMemoryBurnSet().consume
    );
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
    const handleHash = await stack.walletClient.writeContract({
      chain: foundry,
      address: CANONICAL_ENTRYPOINT_V07,
      abi: entryPointV07Abi,
      functionName: "handleOps",
      args: [[final.userOp], stack.account.address],
      account: stack.account,
      gas: 3_000_000n,
    });
    const receipt = await stack.publicClient.waitForTransactionReceipt({
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
    expect(verifierAfter.publicSeed).not.toBe(currentVerifier.publicSeed);
  }, 90_000);

  test("verifierKeyUsed slot derivation pins the paymaster's ERC-7201 layout", async () => {
    // Pins the SDK's `paymasterVerifierKeyUsedSlot` codec helper against
    // the deployed paymaster's storage layout. If the contract-side
    // namespace (`QuipPaymasterStorage`) shifts or its `verifierKeyUsed`
    // mapping moves, `simulateUserOp`'s `NextVerifierKeyInUse` detection
    // silently breaks — this test catches that.
    //
    // Slot semantics under the deployed paymaster: `verifierKeyUsed[hash]`
    // is set when a verifier is registered via `setPqVerifier` (the
    // contract uses it to enforce one-wallet-per-verifier via
    // `VerifierKeyInUse`). It stays set after rotation. So an unregistered
    // verifier reads zero; a registered (or rotated-through) verifier
    // reads non-zero. The SDK's `simulateUserOp` only needs to detect the
    // non-zero state.
    const { walletAddress } = await freshWallet(0x7a);
    const pmClient = makePaymasterClient();

    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x7b),
      createInMemoryBurnSet().consume
    );
    const operatorVault = toHex(new Uint8Array(32).fill(0x7b));
    const currentVerifier = operator.generateKeyPair(operatorVault).publicKey;
    const slotForCurrent = paymasterVerifierKeyUsedSlot(currentVerifier);

    // Before registration: slot must be zero — the verifier has never
    // touched paymaster state.
    const preSlot = await stack.publicClient.getStorageAt({
      address: paymasterAddress,
      slot: slotForCurrent,
    });
    expect(preSlot === undefined ? 0n : BigInt(preSlot)).toBe(0n);

    // Register the verifier. This commits to `verifierKeyUsed` so the
    // SDK's slot derivation must surface a non-zero value here.
    await pmClient.setPqVerifier(walletAddress, currentVerifier);
    const postSlot = await stack.publicClient.getStorageAt({
      address: paymasterAddress,
      slot: slotForCurrent,
    });
    expect(postSlot).toBeDefined();
    expect(BigInt(postSlot!)).not.toBe(0n);

    // A verifier the paymaster has never seen hashes to a slot whose
    // value is zero — confirms the slot derivation isn't aliasing
    // unrelated storage and the per-verifier mapping is keyed correctly.
    const unseenOperator = new QuipSigner(
      new Uint8Array(32).fill(0x7c),
      createInMemoryBurnSet().consume
    );
    const unseenVault = toHex(new Uint8Array(32).fill(0x7c));
    const unseenVerifier = unseenOperator
      .generateKeyPair(unseenVault)
      .publicKey;
    const slotForUnseen = paymasterVerifierKeyUsedSlot(unseenVerifier);
    expect(slotForUnseen).not.toBe(slotForCurrent);
    const unseenSlot = await stack.publicClient.getStorageAt({
      address: paymasterAddress,
      slot: slotForUnseen,
    });
    expect(unseenSlot === undefined ? 0n : BigInt(unseenSlot)).toBe(0n);
  }, 90_000);
});

describe("simulateUserOp — paymaster rejection paths", () => {
  test("NoVerifierRegistered: paymaster has no verifier for sender", async () => {
    const { client: walletSdk, walletAddress } = await freshWallet(0x60);
    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x61),
      createInMemoryBurnSet().consume
    );
    const operatorVault = toHex(new Uint8Array(32).fill(0x61));
    const verifier = operator.generateKeyPair(operatorVault).publicKey;

    // DO NOT register a verifier for this wallet.
    const prepared = await walletSdk.prepareExecuteUserOp(
      zeroAddress,
      0n,
      "0x"
    );
    // We can't reach this code path via `sponsorUserOp` anymore — N8's
    // client-side pre-flight throws PqVerifierNotRegisteredError before
    // signing. Use the lower-level codec helper to hand-roll the
    // paymasterAndData so we can still exercise `simulateUserOp`'s
    // `NoVerifierRegistered` branch.
    const nextVerifier = operator.generateKeyPair(operatorVault).publicKey;
    const { paymasterAndData } = await buildSignedPaymasterAndData({
      signer: operator,
      vaultId: operatorVault,
      paymaster: paymasterAddress,
      chainId: BigInt(foundry.id),
      userOp: prepared.userOp,
      currentVerifier: verifier,
      nextVerifier,
      validUntil: 0,
      validAfter: 0,
    });
    const sponsoredUserOp = { ...prepared.userOp, paymasterAndData };
    void walletAddress;

    const sim = await walletSdk.simulateUserOp(sponsoredUserOp);
    expect(sim.paymasterValidation).toBe(
      PaymasterValidationFailure.NoVerifierRegistered
    );
    expect(sim.keysBurnedIfRevert.paymaster).toBe(false);
  }, 60_000);

  test("ZeroNextVerifier: paymasterAndData has zero nextVerifier", async () => {
    const { client: walletSdk, walletAddress } = await freshWallet(0x62);
    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x63),
      createInMemoryBurnSet().consume
    );
    const operatorVault = toHex(new Uint8Array(32).fill(0x63));
    const currentVerifier = operator.generateKeyPair(operatorVault).publicKey;
    const pmClient = makePaymasterClient();
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
    const { client: walletSdk, walletAddress } = await freshWallet(0x64);
    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x65),
      createInMemoryBurnSet().consume
    );
    const operatorVault = toHex(new Uint8Array(32).fill(0x65));
    const currentVerifier = operator.generateKeyPair(operatorVault).publicKey;
    const pmClient = makePaymasterClient();
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
    const { client: walletSdkA, walletAddress: walletA } = await freshWallet(
      0x66
    );
    const { client: walletSdkB, walletAddress: walletB } = await freshWallet(
      0x67
    );

    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x68),
      createInMemoryBurnSet().consume
    );
    const operatorVault = toHex(new Uint8Array(32).fill(0x68));
    const verifierA = operator.generateKeyPair(operatorVault).publicKey;
    const verifierB_current = operator.generateKeyPair(operatorVault).publicKey;

    const pmClient = makePaymasterClient();
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
    const { client: walletSdk, walletAddress } = await freshWallet(0x69);
    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x6a),
      createInMemoryBurnSet().consume
    );
    const operatorVault = toHex(new Uint8Array(32).fill(0x6a));
    const currentVerifier = operator.generateKeyPair(operatorVault).publicKey;
    const pmClient = makePaymasterClient();
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

describe("sponsorUserOp client-side pre-flight", () => {
  test("throws PqVerifierNotRegisteredError when no verifier is set for the sender", async () => {
    const { client: walletSdk } = await freshWallet(0x80);
    const pmClient = makePaymasterClient();
    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x81),
      createInMemoryBurnSet().consume
    );
    const operatorVault = toHex(new Uint8Array(32).fill(0x81));
    const verifier = operator.generateKeyPair(operatorVault).publicKey;

    // DO NOT setPqVerifier — pre-flight should throw.
    const prepared = await walletSdk.prepareExecuteUserOp(
      zeroAddress,
      0n,
      "0x"
    );
    await expect(
      pmClient.sponsorUserOp({
        userOp: prepared.userOp,
        operatorSigner: operator,
        vaultId: operatorVault,
        currentVerifier: verifier,
      })
    ).rejects.toBeInstanceOf(PqVerifierNotRegisteredError);
  }, 60_000);

  test("throws VerifierMismatchError when currentVerifier doesn't match on-chain", async () => {
    const { client: walletSdk, walletAddress } = await freshWallet(0x82);
    const pmClient = makePaymasterClient();
    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x83),
      createInMemoryBurnSet().consume
    );
    const operatorVault = toHex(new Uint8Array(32).fill(0x83));

    // Register one verifier on-chain…
    const onChainVerifier = operator.generateKeyPair(operatorVault).publicKey;
    await pmClient.setPqVerifier(walletAddress, onChainVerifier);

    // …but pass a DIFFERENT one as currentVerifier.
    const wrongVerifier = operator.generateKeyPair(operatorVault).publicKey;

    const prepared = await walletSdk.prepareExecuteUserOp(
      zeroAddress,
      0n,
      "0x"
    );
    let caught: unknown = null;
    try {
      await pmClient.sponsorUserOp({
        userOp: prepared.userOp,
        operatorSigner: operator,
        vaultId: operatorVault,
        currentVerifier: wrongVerifier,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(VerifierMismatchError);
    const err = caught as VerifierMismatchError;
    expect(err.sender).toBe(walletAddress);
    expect(err.suppliedVerifier.publicSeed).toBe(wrongVerifier.publicSeed);
    expect(err.onChainVerifier.publicSeed).toBe(onChainVerifier.publicSeed);
  }, 60_000);

  test("sponsorUserOp return value includes currentVerifier alongside nextVerifier", async () => {
    const { client: walletSdk, walletAddress } = await freshWallet(0x84);
    const pmClient = makePaymasterClient();
    const operator = new QuipSigner(
      new Uint8Array(32).fill(0x85),
      createInMemoryBurnSet().consume
    );
    const operatorVault = toHex(new Uint8Array(32).fill(0x85));
    const currentVerifier = operator.generateKeyPair(operatorVault).publicKey;
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
      currentVerifier,
    });
    expect(sponsored.currentVerifier.publicSeed).toBe(currentVerifier.publicSeed);
    expect(sponsored.currentVerifier.publicKeyHash).toBe(
      currentVerifier.publicKeyHash
    );
    expect(sponsored.nextVerifier.publicSeed).not.toBe(
      currentVerifier.publicSeed
    );
  }, 60_000);
});
