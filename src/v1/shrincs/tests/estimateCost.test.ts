// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Address, type PublicClient } from "viem";

import { estimateTxCost, resolveFeePerGas } from "../estimateCost.js";
import { applyGasMultiplier } from "../gas.js";

const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const TARGET = "0x00000000000000000000000000000000000000f1" as Address;

interface EstimatedCall {
  stateOverride?: { address: Address; balance: bigint }[];
}

interface FakeChainState {
  gasEstimate: bigint;
  maxFeePerGas?: bigint;
  baseFeePerGas: bigint | null;
  legacyGasPrice: bigint;
}

function fakeChain(overrides: Partial<FakeChainState> = {}) {
  const state: FakeChainState = {
    gasEstimate: 200_000n,
    maxFeePerGas: 2_000_000_000n,
    baseFeePerGas: 1_400_000_000n,
    legacyGasPrice: 7n,
    ...overrides,
  };
  const estimatedCalls: EstimatedCall[] = [];

  const publicClient = {
    getBalance: async () => 0n,
    estimateContractGas: async (call: EstimatedCall) => {
      estimatedCalls.push(call);
      return state.gasEstimate;
    },
    estimateFeesPerGas: async () => {
      if (state.maxFeePerGas === undefined) throw new Error("no 1559 support");
      return { maxFeePerGas: state.maxFeePerGas, maxPriorityFeePerGas: 1n };
    },
    getGasPrice: async () => state.legacyGasPrice,
    getBlock: async () => ({ baseFeePerGas: state.baseFeePerGas }),
  } as unknown as PublicClient;

  return { publicClient, estimatedCalls };
}

const contractCall = {
  address: TARGET,
  abi: [] as readonly unknown[],
  functionName: "doThing",
  args: [],
  value: 5n,
  account: ACCOUNT,
};

describe("estimateTxCost", () => {
  it("returns the measured gas and the padded ceiling", async () => {
    const chain = fakeChain();

    const estimate = await estimateTxCost({
      publicClient: chain.publicClient,
      account: ACCOUNT,
      contractCall,
      totalValue: 5n,
      opts: {},
    });

    expect(estimate.expectedGasUnits).toBe(200_000n);
    expect(estimate.gasUnits).toBe(applyGasMultiplier(200_000n, {}));
    expect(estimate.expectedGasPrice).toBe(1_400_000_001n);
    expect(estimate.gasPrice).toBe(2_000_000_000n);
    expect(chain.estimatedCalls).toHaveLength(1);
  });

  it("funds the sender in simulation for the value plus a gas allowance", async () => {
    const chain = fakeChain();

    await estimateTxCost({
      publicClient: chain.publicClient,
      account: ACCOUNT,
      contractCall,
      totalValue: 5n,
      opts: {},
    });

    const override = chain.estimatedCalls[0]!.stateOverride![0]!;
    expect(override.address).toBe(ACCOUNT);
    expect(override.balance).toBe(5n + 2_000_000_000n * 30_000_000n);
  });
});

describe("resolveFeePerGas", () => {
  it("quotes the cap and the current base fee separately", async () => {
    const { publicClient } = fakeChain();

    await expect(resolveFeePerGas(publicClient, {})).resolves.toEqual({
      cap: 2_000_000_000n,
      expected: 1_400_000_001n,
    });
  });

  it("quotes one price when the caller pins a fee", async () => {
    const { publicClient } = fakeChain();

    await expect(
      resolveFeePerGas(publicClient, { maxFeePerGas: 99n })
    ).resolves.toEqual({ cap: 99n, expected: 99n });
  });

  it("quotes one price on a chain without EIP-1559", async () => {
    const { publicClient } = fakeChain({ maxFeePerGas: undefined });

    await expect(resolveFeePerGas(publicClient, {})).resolves.toEqual({
      cap: 7n,
      expected: 7n,
    });
  });

  it("quotes one price on a chain with no base fee", async () => {
    const { publicClient } = fakeChain({ baseFeePerGas: null });

    await expect(resolveFeePerGas(publicClient, {})).resolves.toEqual({
      cap: 2_000_000_000n,
      expected: 2_000_000_000n,
    });
  });
});
