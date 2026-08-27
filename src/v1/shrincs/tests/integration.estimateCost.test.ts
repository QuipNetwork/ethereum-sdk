// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { parseEther } from "viem";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, it } from "@jest/globals";

import { walletFactoryAbi } from "../../abi/WalletFactory.js";
import {
  type ShrincsAnvilStack,
  SHRINCS_ANVIL_PORTS,
  createFreshShrincsWallet,
  makeShrincsFactoryClient,
  makeShrincsSigner,
  setupShrincsAnvilStack,
  stopShrincsAnvilStack,
} from "./utils/shrincsAnvilFixture.js";

const MAX_SIGS = 40;

let stack: ShrincsAnvilStack;

beforeAll(async () => {
  stack = await setupShrincsAnvilStack({ port: SHRINCS_ANVIL_PORTS.estimate });
}, 120_000);

afterAll(async () => {
  await stopShrincsAnvilStack(stack);
}, 10_000);

/// Distinct main + ERC-1271 derivation indices per test so deployments never
/// alias.
function indices(seed: number): {
  derivationIndex: number;
  erc1271Index: number;
} {
  return { derivationIndex: seed, erc1271Index: seed + 1000 };
}

describe("cost estimation against a live anvil stack", () => {
  it("prices the deployment createShrincsWallet then lands", async () => {
    const signer = await makeShrincsSigner(0x31);
    const { derivationIndex, erc1271Index } = indices(0x31);
    const params = {
      signer,
      maxSignatures: MAX_SIGS,
      derivationIndex,
      erc1271: { derivationIndex: erc1271Index, maxSignatures: MAX_SIGS },
    };
    const factory = makeShrincsFactoryClient(stack);

    const estimate = await factory.estimateCreationCost(params);
    expect(estimate.gasUnits).toBeGreaterThan(0n);
    expect(estimate.gasPrice).toBeGreaterThan(0n);
    expect(estimate.expectedGasPrice).toBeLessThanOrEqual(estimate.gasPrice);

    // The same params deploy for real: the estimate priced exactly this call.
    const client = await factory.createShrincsWallet(params);
    const state = await client.getWalletState();
    expect(state.maxSignatures).toBe(MAX_SIGS);

    const receipt = await stack.publicClient.getTransactionReceipt({
      hash: (await stack.publicClient.getBlock({ includeTransactions: true }))
        .transactions[0]!.hash,
    });
    const drift = Math.abs(
      Number(estimate.expectedGasUnits - receipt.gasUsed) /
        Number(receipt.gasUsed)
    );
    expect(estimate.expectedGasUnits).toBeGreaterThanOrEqual(receipt.gasUsed);
    expect(drift).toBeLessThan(0.05);
    expect(estimate.gasUnits).toBeGreaterThan(receipt.gasUsed);
  }, 180_000);

  it("prepareExecute prices and then sends the one signature it made", async () => {
    await stack.testClient.setBalance({
      address: stack.account.address,
      value: parseEther("100"),
    });
    const { client } = await createFreshShrincsWallet(stack, 0x41, {
      maxSignatures: MAX_SIGS,
    });
    const transfer = {
      target: "0x000000000000000000000000000000000000d00d" as const,
      value: parseEther("0.01"),
    };

    const before = (await client.getWalletState()).statefulLeavesUsed;
    const prepared = await client.prepareExecute(transfer);
    expect(prepared.estimate.expectedGasUnits).toBeGreaterThan(0n);
    // Preparing signs in memory only: nothing is consumed on-chain yet.
    expect((await client.getWalletState()).statefulLeavesUsed).toBe(before);

    const receipt = await prepared.send();
    const drift = Math.abs(
      Number(prepared.estimate.expectedGasUnits - receipt.gasUsed) /
        Number(receipt.gasUsed)
    );
    expect(prepared.estimate.expectedGasUnits).toBeGreaterThanOrEqual(
      receipt.gasUsed
    );
    expect(drift).toBeLessThan(0.05);
    expect(prepared.estimate.gasUnits).toBeGreaterThan(receipt.gasUsed);

    // Exactly one leaf — the one the estimate was signed at — is consumed.
    expect((await client.getWalletState()).statefulLeavesUsed).toBe(before + 1);
    await expect(prepared.send()).rejects.toThrow("already sent");
  }, 180_000);

  it("prices a charged deployment for an account holding nothing", async () => {
    const factory = makeShrincsFactoryClient(stack);
    const fee = parseEther("0.01");
    const hash = await stack.walletClient.writeContract({
      chain: foundry,
      account: stack.account,
      address: stack.factoryAddress,
      abi: walletFactoryAbi,
      functionName: "setCreationFee",
      args: [fee],
    });
    await stack.publicClient.waitForTransactionReceipt({ hash });
    await stack.testClient.setBalance({
      address: stack.account.address,
      value: 0n,
    });

    const signer = await makeShrincsSigner(0x51);
    const { derivationIndex, erc1271Index } = indices(0x51);
    const estimate = await factory.estimateCreationCost({
      signer,
      maxSignatures: MAX_SIGS,
      derivationIndex,
      erc1271: { derivationIndex: erc1271Index, maxSignatures: MAX_SIGS },
    });

    expect(estimate.creationFee).toBe(fee);
    expect(estimate.gasUnits).toBeGreaterThan(0n);
  }, 180_000);
});
