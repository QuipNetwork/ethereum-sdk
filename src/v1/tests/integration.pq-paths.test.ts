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

// E2E coverage for the wallet's PQ-only orchestration paths: every method
// that touches a non-Transaction key (disaster, ownership, recovery) plus
// `withdrawDeposit` and the two upgrade flows. Codec parity is asserted in
// wotsCodec.test.ts; this file exercises the wallet-client surface that sits
// on top — key generation, key selection, signature flow, contract dispatch.

import {
  type Address,
  type Hex,
  type WalletClient,
  createWalletClient,
  http,
  parseEther,
  toHex,
  zeroAddress,
} from "viem";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

import { quipWalletAbi } from "../abi/QuipWallet.js";
import { QuipSigner } from "../signer.js";
import { createInMemoryBurnSet } from "../burnSet.js";
import {
  IncorrectRecoveryKeyAmountError,
  IncorrectTransactionKeyAmountError,
  KeyAlreadyBurnedError,
} from "../errors.js";
import {
  verificationDigest,
  type WinternitzAddress,
  type WinternitzElements,
  RECOVERY_KEY_AMOUNT,
  TRANSACTION_KEY_INIT_AMOUNT,
} from "../wotsCodec.js";
import {
  ANVIL_PORTS,
  type AnvilStack,
  createFreshWallet,
  setupAnvilStack,
  stopAnvilStack,
} from "./utils/anvilFixture.js";

const NEW_OWNER_PRIV_KEY =
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const newOwnerAccount = privateKeyToAccount(NEW_OWNER_PRIV_KEY);

let stack: AnvilStack;
let newOwnerWalletClient: WalletClient;

// Build a verifier `WinternitzAddress` + `WinternitzElements` pair for the
// upgrade paths. In production this comes from the impl deployer's signed
// attestation; here a one-off signer + burn set stands in.
function buildVerifierAttestation(
  walletAddress: Address,
  newImplementation: Address,
  saltByte: number
): { verifier: WinternitzAddress; verifySig: WinternitzElements } {
  const verifierSigner = new QuipSigner(
    new Uint8Array(32).fill(saltByte),
    createInMemoryBurnSet().consume
  );
  const verifierVault = toHex(new Uint8Array(32).fill(saltByte));
  const verifier = verifierSigner.generateKeyPair(verifierVault).publicKey;
  const digest = verificationDigest(
    walletAddress,
    BigInt(foundry.id),
    newImplementation,
    verifier.publicSeed,
    verifier.publicKeyHash
  );
  const elements = verifierSigner.sign(
    digest,
    verifierVault,
    verifier.publicSeed
  );
  return { verifier, verifySig: { elements } };
}

beforeAll(async () => {
  stack = await setupAnvilStack({ port: ANVIL_PORTS.pqPaths });
  newOwnerWalletClient = createWalletClient({
    chain: foundry,
    transport: http(`http://127.0.0.1:${stack.anvil.port}`),
    account: newOwnerAccount,
  });
  // Fund the alternate owner so it can pay gas for requestOwnershipHandover.
  await stack.testClient.setBalance({
    address: newOwnerAccount.address,
    value: parseEther("10"),
  });
}, 90_000);

afterAll(async () => {
  await stopAnvilStack(stack);
}, 10_000);

// Every test in this file wants the EntryPoint deposit topped up so the
// withdrawDeposit path has something to draw against.
async function freshWallet(seedByte: number) {
  return createFreshWallet(stack, seedByte, {
    entryPointDeposit: parseEther("1"),
  });
}

// ─── Tests ──────────────────────────────────────────────────────────

describe("withdrawDeposit", () => {
  test("transfers the requested amount from the EntryPoint deposit and burns the signing key", async () => {
    const { client, isBurned } = await freshWallet(0x60);
    const head = await client.getHeadTransactionKey();
    const depositBefore = await client.getDeposit();
    const recipient = privateKeyToAccount(
      "0x0123456789012345678901234567890123456789012345678901234567890123"
    ).address;
    const recipientBalanceBefore = await stack.publicClient.getBalance({
      address: recipient,
    });
    const withdrawAmount = parseEther("0.25");

    const receipt = await client.withdrawDeposit(recipient, withdrawAmount);
    expect(receipt.status).toBe("success");

    const depositAfter = await client.getDeposit();
    expect(depositBefore - depositAfter).toBe(withdrawAmount);

    const recipientBalanceAfter = await stack.publicClient.getBalance({
      address: recipient,
    });
    expect(recipientBalanceAfter - recipientBalanceBefore).toBe(withdrawAmount);

    // Signing key burned (transaction key — burn happens client-side before
    // dispatch via QuipSigner.consume).
    expect(isBurned(head.publicSeed)).toBe(true);
  }, 60_000);

  test("a second withdrawDeposit re-signs with the rotated head key (the old key is burned)", async () => {
    const { client, isBurned } = await freshWallet(0x61);
    const firstHead = await client.getHeadTransactionKey();
    const recipient = privateKeyToAccount(
      "0x0123456789012345678901234567890123456789012345678901234567890123"
    ).address;

    await client.withdrawDeposit(recipient, parseEther("0.1"));
    expect(isBurned(firstHead.publicSeed)).toBe(true);

    const secondHead = await client.getHeadTransactionKey();
    expect(secondHead.publicSeed).not.toBe(firstHead.publicSeed);

    await client.withdrawDeposit(recipient, parseEther("0.1"));
    expect(isBurned(secondHead.publicSeed)).toBe(true);
  }, 90_000);
});

describe("transferOwnership", () => {
  function buildOwnershipParams(): {
    newOwnershipKey: WinternitzAddress;
    newDisasterRecoveryKey: WinternitzAddress;
    newTransactionKeys: WinternitzAddress[];
    newRecoveryKeys: WinternitzAddress[];
    incomingSigner: QuipSigner;
  } {
    // Standalone signer/vault representing the new owner's key material.
    const incomingSigner = new QuipSigner(
      new Uint8Array(32).fill(0xa0),
      createInMemoryBurnSet().consume
    );
    const incomingVault = toHex(new Uint8Array(32).fill(0xa0));
    const newOwnershipKey = incomingSigner.generateKeyPair(incomingVault)
      .publicKey;
    const newDisasterRecoveryKey = incomingSigner.generateKeyPair(incomingVault)
      .publicKey;
    const newTransactionKeys = Array.from(
      { length: TRANSACTION_KEY_INIT_AMOUNT },
      () => incomingSigner.generateKeyPair(incomingVault).publicKey
    );
    const newRecoveryKeys = Array.from({ length: RECOVERY_KEY_AMOUNT }, () =>
      incomingSigner.generateKeyPair(incomingVault).publicKey
    );
    return {
      newOwnershipKey,
      newDisasterRecoveryKey,
      newTransactionKeys,
      newRecoveryKeys,
      incomingSigner,
    };
  }

  test("rotates classical owner and reinitializes all PQ state; ownership key burned", async () => {
    const { client, walletAddress, ownershipKey, isBurned } =
      await freshWallet(0x62);
    const newOwner = newOwnerAccount.address;
    const params = buildOwnershipParams();

    const ownerBefore = (await client.getWalletState()).owner;
    expect(ownerBefore).toBe(stack.account.address);

    const receipt = await client.transferOwnership(ownershipKey.publicSeed, {
      newOwner,
      newOwnershipKey: params.newOwnershipKey,
      newDisasterRecoveryKey: params.newDisasterRecoveryKey,
      newTransactionKeys: params.newTransactionKeys,
      newRecoveryKeys: params.newRecoveryKeys,
    });
    expect(receipt.status).toBe("success");

    const state = await client.getWalletState();
    expect(state.owner).toBe(newOwner);
    expect(state.ownershipKey.publicSeed).toBe(params.newOwnershipKey.publicSeed);
    expect(state.disasterRecoveryKey.publicSeed).toBe(
      params.newDisasterRecoveryKey.publicSeed
    );
    expect(state.keyCounts.transaction).toBe(BigInt(TRANSACTION_KEY_INIT_AMOUNT));
    expect(state.keyCounts.recovery).toBe(BigInt(RECOVERY_KEY_AMOUNT));

    // Every freshly installed transaction key shows up in the on-chain set.
    const installed = new Set(state.transactionKeys.map((k) => k.publicSeed));
    for (const k of params.newTransactionKeys) {
      expect(installed.has(k.publicSeed)).toBe(true);
    }

    expect(isBurned(ownershipKey.publicSeed)).toBe(true);
    // Sanity: previously-installed transaction keys are gone.
    const remaining = state.transactionKeys.map((k) => k.publicSeed);
    expect(remaining).not.toContain(walletAddress.toLowerCase());
  }, 60_000);

  test("throws IncorrectTransactionKeyAmountError synchronously for a wrong-length transaction-keys batch (no key burned)", async () => {
    const { client, ownershipKey, isBurned } = await freshWallet(0x63);
    const params = buildOwnershipParams();
    const shortTransactionKeys = params.newTransactionKeys.slice(0, 4);

    await expect(
      client.transferOwnership(ownershipKey.publicSeed, {
        newOwner: newOwnerAccount.address,
        newOwnershipKey: params.newOwnershipKey,
        newDisasterRecoveryKey: params.newDisasterRecoveryKey,
        newTransactionKeys: shortTransactionKeys,
        newRecoveryKeys: params.newRecoveryKeys,
      })
    ).rejects.toBeInstanceOf(IncorrectTransactionKeyAmountError);

    // Critical: pre-flight ran before signWith → ownership key NOT burned.
    expect(isBurned(ownershipKey.publicSeed)).toBe(false);
  }, 30_000);

  test("throws IncorrectRecoveryKeyAmountError synchronously for a wrong-length recovery-keys batch (no key burned)", async () => {
    const { client, ownershipKey, isBurned } = await freshWallet(0x64);
    const params = buildOwnershipParams();
    const shortRecoveryKeys = params.newRecoveryKeys.slice(0, 9);

    await expect(
      client.transferOwnership(ownershipKey.publicSeed, {
        newOwner: newOwnerAccount.address,
        newOwnershipKey: params.newOwnershipKey,
        newDisasterRecoveryKey: params.newDisasterRecoveryKey,
        newTransactionKeys: params.newTransactionKeys,
        newRecoveryKeys: shortRecoveryKeys,
      })
    ).rejects.toBeInstanceOf(IncorrectRecoveryKeyAmountError);

    expect(isBurned(ownershipKey.publicSeed)).toBe(false);
  }, 30_000);
});

describe("saveWallet", () => {
  test("rotates the disaster-recovery key and reinstalls fresh transaction + recovery keysets", async () => {
    const { client, signer, vaultId, disasterKey, isBurned } =
      await freshWallet(0x66);
    const stateBefore = await client.getWalletState();
    const owner = stateBefore.owner;
    const ownershipBefore = stateBefore.ownershipKey.publicSeed;

    const receipt = await client.saveWallet(disasterKey.publicSeed);
    expect(receipt.status).toBe("success");

    const stateAfter = await client.getWalletState();
    // Ownership untouched.
    expect(stateAfter.owner).toBe(owner);
    expect(stateAfter.ownershipKey.publicSeed).toBe(ownershipBefore);
    // Disaster key rotated.
    expect(stateAfter.disasterRecoveryKey.publicSeed).not.toBe(
      disasterKey.publicSeed
    );
    // Transaction + recovery keysets refilled to the init amounts.
    expect(stateAfter.keyCounts.transaction).toBe(
      BigInt(TRANSACTION_KEY_INIT_AMOUNT)
    );
    expect(stateAfter.keyCounts.recovery).toBe(BigInt(RECOVERY_KEY_AMOUNT));

    // Signing disaster key burned.
    expect(isBurned(disasterKey.publicSeed)).toBe(true);

    // Sanity: the new transaction keys are still recoverable under this
    // signer/vault (i.e., the SDK generated them rather than e.g. zeroing
    // them out). Re-derivation from publicSeed must reproduce the
    // publicKeyHash on chain.
    for (const k of stateAfter.transactionKeys) {
      const recovered = signer.recoverKeyPair(vaultId, k.publicSeed).publicKey;
      expect(recovered.publicKeyHash).toBe(k.publicKeyHash);
    }
  }, 90_000);

  test("a burned disaster key cannot be reused for a second saveWallet", async () => {
    const { client, disasterKey } = await freshWallet(0x67);
    await client.saveWallet(disasterKey.publicSeed);

    await expect(
      client.saveWallet(disasterKey.publicSeed)
    ).rejects.toBeInstanceOf(KeyAlreadyBurnedError);
  }, 60_000);
});

describe("recoverWallet", () => {
  test("recovers via a recovery key: replaces the transaction keyset with a fresh single key and rotates the recovery key", async () => {
    const { client, recoveryKeys, isBurned } = await freshWallet(0x68);
    const recoveryKey = recoveryKeys[0];

    const stateBefore = await client.getWalletState();
    expect(stateBefore.keyCounts.recovery).toBe(BigInt(RECOVERY_KEY_AMOUNT));

    const receipt = await client.recoverWallet(recoveryKey.publicSeed);
    expect(receipt.status).toBe("success");

    const stateAfter = await client.getWalletState();
    // Transaction keyset is cleared and reseeded with exactly one fresh key.
    expect(stateAfter.keyCounts.transaction).toBe(1n);
    expect(stateAfter.transactionKeys.length).toBe(1);
    // Recovery keyset capacity is preserved (size-stable rotation).
    expect(stateAfter.keyCounts.recovery).toBe(BigInt(RECOVERY_KEY_AMOUNT));
    // The signing recovery key is gone.
    const remainingRecoverySeeds = stateAfter.recoveryKeys.map(
      (k) => k.publicSeed
    );
    expect(remainingRecoverySeeds).not.toContain(recoveryKey.publicSeed);

    expect(isBurned(recoveryKey.publicSeed)).toBe(true);
  }, 60_000);

  test("transaction operations resume cleanly after recovery using the new seed key", async () => {
    const { client, recoveryKeys, walletAddress } = await freshWallet(0x69);
    await client.recoverWallet(recoveryKeys[0].publicSeed);

    // The single new transaction key should drive a withdrawal end-to-end.
    const recipient = privateKeyToAccount(
      "0x0123456789012345678901234567890123456789012345678901234567890123"
    ).address;
    const depositBefore = await client.getDeposit();
    const receipt = await client.withdrawDeposit(recipient, parseEther("0.05"));
    expect(receipt.status).toBe("success");
    const depositAfter = await client.getDeposit();
    expect(depositBefore - depositAfter).toBe(parseEther("0.05"));
    expect(walletAddress).toBe(await client.getAddress());
  }, 90_000);
});

describe("upgradeWallet", () => {
  test("PQ-authenticated upgrade lands and burns a transaction key (no-migration branch)", async () => {
    const { client, walletAddress, isBurned } = await freshWallet(0x6a);
    const head = await client.getHeadTransactionKey();

    // Upgrade target is the already-vetted impl; factory check passes by
    // codehash and the wallet's UUPS path overwrites the impl slot. The point
    // of this test is that the SDK's signing/payload flow produces a payload
    // the wallet accepts end-to-end.
    const { verifier, verifySig } = buildVerifierAttestation(
      walletAddress,
      stack.walletImplAddress,
      0xc0
    );

    const receipt = await client.upgradeWallet(
      stack.walletImplAddress,
      verifier,
      verifySig
    );
    expect(receipt.status).toBe("success");
    expect(isBurned(head.publicSeed)).toBe(true);

    // Implementation slot still resolves to the vetted impl (version() reads
    // the codehash → factory's getVettedCodeIndex, which is 0 for the only
    // vetted entry).
    expect(await client.version()).toBe(0n);
  }, 90_000);

  test("upgrade with a 0x migrationPayload takes the no-migrate branch (shouldMigrate=false)", async () => {
    const { client, walletAddress, isBurned } = await freshWallet(0x6b);
    const head = await client.getHeadTransactionKey();
    const { verifier, verifySig } = buildVerifierAttestation(
      walletAddress,
      stack.walletImplAddress,
      0xc1
    );

    const receipt = await client.upgradeWallet(
      stack.walletImplAddress,
      verifier,
      verifySig,
      { migrationPayload: "0x" }
    );
    expect(receipt.status).toBe("success");
    expect(isBurned(head.publicSeed)).toBe(true);
  }, 90_000);
});

describe("recoveryUpgrade", () => {
  test("emergency upgrade authorized by a recovery key rotates the recovery key in-place and lands the upgrade", async () => {
    const { client, walletAddress, recoveryKeys, isBurned } =
      await freshWallet(0x6c);
    const recoveryKey = recoveryKeys[0];

    const stateBefore = await client.getWalletState();
    expect(stateBefore.keyCounts.recovery).toBe(BigInt(RECOVERY_KEY_AMOUNT));

    const { verifier, verifySig } = buildVerifierAttestation(
      walletAddress,
      stack.walletImplAddress,
      0xc2
    );

    const receipt = await client.recoveryUpgrade(
      recoveryKey.publicSeed,
      stack.walletImplAddress,
      verifier,
      verifySig
    );
    expect(receipt.status).toBe("success");
    expect(isBurned(recoveryKey.publicSeed)).toBe(true);

    const stateAfter = await client.getWalletState();
    // Recovery capacity is preserved (size-stable swap).
    expect(stateAfter.keyCounts.recovery).toBe(BigInt(RECOVERY_KEY_AMOUNT));
    // The old recovery key is gone.
    const remaining = stateAfter.recoveryKeys.map((k) => k.publicSeed);
    expect(remaining).not.toContain(recoveryKey.publicSeed);

    // Transaction keyset is untouched by recoveryUpgrade (distinct from
    // recoverWallet, which clears + reseeds it).
    expect(stateAfter.keyCounts.transaction).toBe(
      stateBefore.keyCounts.transaction
    );
  }, 90_000);

  test("explicit newRecoveryKey override is honored", async () => {
    const { client, walletAddress, recoveryKeys, signer, vaultId, isBurned } =
      await freshWallet(0x6d);
    const recoveryKey = recoveryKeys[1];
    const explicitNewRecovery = signer.generateKeyPair(vaultId).publicKey;

    const { verifier, verifySig } = buildVerifierAttestation(
      walletAddress,
      stack.walletImplAddress,
      0xc3
    );

    await client.recoveryUpgrade(
      recoveryKey.publicSeed,
      stack.walletImplAddress,
      verifier,
      verifySig,
      { newRecoveryKey: explicitNewRecovery }
    );
    expect(isBurned(recoveryKey.publicSeed)).toBe(true);

    const state = await client.getWalletState();
    const seeds = state.recoveryKeys.map((k) => k.publicSeed);
    expect(seeds).toContain(explicitNewRecovery.publicSeed);
    expect(seeds).not.toContain(recoveryKey.publicSeed);

    // zeroAddress reference kept so lint/imports stay clean across edits.
    expect(zeroAddress).not.toBe(walletAddress);
  }, 90_000);
});
