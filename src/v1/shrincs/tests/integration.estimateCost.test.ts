// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Hex, keccak256, parseEther, toHex } from "viem";
import { foundry } from "viem/chains";
import { afterAll, beforeAll, describe, expect, it } from "@jest/globals";

import { walletFactoryAbi } from "../../abi/WalletFactory.js";
import { encodeInitPayload } from "../shrincsCodec.js";
import {
  type ShrincsAnvilStack,
  SHRINCS_ANVIL_PORTS,
  createFreshShrincsWallet,
  makeShrincsFactoryClient,
  makeShrincsSigner,
  setupShrincsAnvilStack,
  stopShrincsAnvilStack,
} from "./utils/shrincsAnvilFixture.js";

const MAX_SIGS = 4;

let stack: ShrincsAnvilStack;

beforeAll(async () => {
  stack = await setupShrincsAnvilStack({ port: SHRINCS_ANVIL_PORTS.estimate });
}, 120_000);

afterAll(async () => {
  await stopShrincsAnvilStack(stack);
}, 10_000);

async function gasForDeploymentWithRealKeyMaterial(
  vaultId: Hex
): Promise<bigint> {
  const creationFee = await stack.publicClient.readContract({
    address: stack.factoryAddress,
    abi: walletFactoryAbi,
    functionName: "creationFee",
  });
  const signer = await makeShrincsSigner(0x31);
  const mainKey = signer.recoverKeyPair(vaultId, { maxSignatures: MAX_SIGS });
  const erc1271Key = signer.recoverKeyPair(("0x" + "31".repeat(32)) as Hex, {
    maxSignatures: MAX_SIGS,
  });
  const code = await stack.publicClient.getCode({
    address: stack.shrincsWalletImpl,
  });
  const index = await stack.publicClient.readContract({
    address: stack.factoryAddress,
    abi: walletFactoryAbi,
    functionName: "getVettedCodeIndex",
    args: [keccak256(code!)],
  });

  return stack.publicClient.estimateContractGas({
    address: stack.factoryAddress,
    abi: walletFactoryAbi,
    functionName: "deploySpecificWalletProxy",
    args: [
      vaultId,
      index,
      stack.account.address,
      encodeInitPayload({
        mainBundle: mainKey.publicKey,
        erc1271Commitment: erc1271Key.publicKeyCommitment,
      }),
    ],
    value: creationFee,
    account: stack.account.address,
  });
}

describe("cost estimation against a live anvil stack", () => {
  it("prices a deployment the wallet's initialize accepts, matching real key material", async () => {
    const vaultId = toHex(new Uint8Array(32).fill(0x31));

    const estimate = await makeShrincsFactoryClient(stack).estimateCreationCost(
      {
        vaultId,
      }
    );

    expect(estimate.gasUnits).toBeGreaterThan(0n);
    expect(estimate.gasPrice).toBeGreaterThan(0n);

    const realKeyMaterialGas = await gasForDeploymentWithRealKeyMaterial(
      vaultId
    );
    const drift = Math.abs(
      Number(estimate.expectedGasUnits - realKeyMaterialGas) /
        Number(realKeyMaterialGas)
    );
    expect(drift).toBeLessThan(0.01);

    expect(estimate.gasUnits).toBeGreaterThan(realKeyMaterialGas);
    expect(estimate.expectedGasPrice).toBeLessThanOrEqual(estimate.gasPrice);
  }, 180_000);

  it("predicts what an execute actually costs", async () => {
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

    const estimate = await client.estimateExecuteCost(transfer);
    const receipt = await client.execute(transfer);

    const drift = Math.abs(
      Number(estimate.expectedGasUnits - receipt.gasUsed) /
        Number(receipt.gasUsed)
    );
    expect(estimate.expectedGasUnits).toBeGreaterThanOrEqual(receipt.gasUsed);
    expect(drift).toBeLessThan(0.05);
    expect(estimate.gasUnits).toBeGreaterThan(receipt.gasUsed);
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

    const estimate = await factory.estimateCreationCost();

    expect(estimate.creationFee).toBe(fee);
    expect(estimate.gasUnits).toBeGreaterThan(0n);
  }, 180_000);
});
