// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  decodeAbiParameters,
  zeroAddress,
} from "viem";

import {
  ShrincsFactoryClient,
  placeholderInitPayload,
} from "../shrincsFactoryClient.js";
import { abiTuples, publicKeyCommitment } from "../shrincsCodec.js";
import { ChainChangedError, WalletAlreadyExistsError } from "../../errors.js";
import { applyGasMultiplier } from "../gas.js";
import { ImplementationNotVettedError } from "../errors.js";

const CHAIN_ID = 8453;
const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const FACTORY = "0x00000000000000000000000000000000000000f1" as Address;
const IMPLEMENTATION = "0x00000000000000000000000000000000000000e1" as Address;
const CREATION_FEE = 1_000_000_000_000_000n;
const VAULT_ID = ("0x" + "77".repeat(32)) as Hex;
const STATEFUL_PUBLIC_KEY_BYTES = 68;

interface EstimatedCall {
  address: Address;
  functionName: string;
  args: [Hex, bigint, Address, Hex];
  value: bigint;
  account: Address;
  stateOverride?: { address: Address; balance: bigint }[];
}

interface FakeChainState {
  wallets: Record<string, Address>;
  vettedIndex: bigint;
  implementationCode: Hex;
  gasEstimate: bigint;
  maxFeePerGas?: bigint;
  baseFeePerGas: bigint | null;
  omitMaxFeePerGas: boolean;
  legacyGasPrice: bigint;
}

function fakeChain(overrides: Partial<FakeChainState> = {}) {
  const state: FakeChainState = {
    wallets: {},
    vettedIndex: 3n,
    implementationCode: "0xfe01",
    gasEstimate: 400_000n,
    maxFeePerGas: 2_000_000_000n,
    baseFeePerGas: 1_400_000_000n,
    omitMaxFeePerGas: false,
    legacyGasPrice: 7n,
    ...overrides,
  };

  const estimatedCalls: EstimatedCall[] = [];
  let balanceReads = 0;
  let writes = 0;

  const publicClient = {
    getChainId: async () => CHAIN_ID,
    getCode: async () => state.implementationCode,
    getBalance: async () => {
      balanceReads += 1;
      return 0n;
    },
    readContract: async ({
      functionName,
      args,
    }: {
      functionName: string;
      args?: unknown[];
    }) => {
      if (functionName === "wallets") {
        return state.wallets[(args?.[0] as Hex).toLowerCase()] ?? zeroAddress;
      }
      if (functionName === "getVettedCodeIndex") return state.vettedIndex;
      if (functionName === "creationFee") return CREATION_FEE;
      throw new Error(`unexpected read: ${functionName}`);
    },
    estimateContractGas: async (call: EstimatedCall) => {
      estimatedCalls.push(call);
      return state.gasEstimate;
    },
    estimateFeesPerGas: async () => {
      if (state.maxFeePerGas === undefined) throw new Error("no 1559 support");
      if (state.omitMaxFeePerGas) return { maxPriorityFeePerGas: 1n };
      return { maxFeePerGas: state.maxFeePerGas, maxPriorityFeePerGas: 1n };
    },
    getGasPrice: async () => state.legacyGasPrice,
    getBlock: async () => ({ baseFeePerGas: state.baseFeePerGas }),
  } as unknown as PublicClient;

  const walletClient = {
    getAddresses: async () => [ACCOUNT],
    writeContract: async () => {
      writes += 1;
      throw new Error("estimation must not write");
    },
  } as unknown as WalletClient;

  return {
    publicClient,
    walletClient,
    estimatedCalls,
    balanceReads: () => balanceReads,
    writes: () => writes,
  };
}

const byteLength = (value: Hex) => (value.length - 2) / 2;

function decodePlaceholderBundle() {
  const [, , bundle] = decodeAbiParameters(
    [
      { name: "commitment", type: "bytes32" },
      { name: "pkSeed", type: "bytes32" },
      abiTuples.publicKey,
      { name: "hashSuite", type: "uint32" },
      { name: "erc1271Commitment", type: "bytes32" },
      { name: "erc1271HashSuite", type: "uint32" },
    ],
    placeholderInitPayload()
  ) as unknown as [
    Hex,
    Hex,
    {
      statefulPublicKey: Hex;
      publicKeyCommitment: Hex;
      pkSeed: Hex;
      hypertreeRoot: Hex;
    }
  ];
  return bundle;
}

function makeClient(chain: ReturnType<typeof fakeChain>) {
  return new ShrincsFactoryClient({
    publicClient: chain.publicClient,
    walletClient: chain.walletClient,
    account: ACCOUNT,
    chainId: CHAIN_ID,
    factoryAddress: FACTORY,
    walletImplementation: IMPLEMENTATION,
  });
}

describe("ShrincsFactoryClient.estimateCreationCost", () => {
  it("prices a deployment without a signer", async () => {
    const chain = fakeChain();

    const estimate = await makeClient(chain).estimateCreationCost();

    expect(estimate.creationFee).toBe(CREATION_FEE);
    expect(estimate.gasPrice).toBe(2_000_000_000n);
    expect(estimate.gasUnits).toBe(applyGasMultiplier(400_000n, {}));
    expect(chain.writes()).toBe(0);
  });

  it("reports the likely cost alongside the ceiling", async () => {
    const chain = fakeChain();

    const estimate = await makeClient(chain).estimateCreationCost();

    expect(estimate.expectedGasUnits).toBe(400_000n);
    expect(estimate.expectedGasPrice).toBe(1_400_000_000n + 1n);
    expect(estimate.expectedGasUnits).toBeLessThan(estimate.gasUnits);
    expect(estimate.expectedGasPrice).toBeLessThan(estimate.gasPrice);
    expect(chain.estimatedCalls).toHaveLength(1);
  });

  it("estimates the same deployment call the create path would send", async () => {
    const chain = fakeChain();

    await makeClient(chain).estimateCreationCost({ vaultId: VAULT_ID });

    const call = chain.estimatedCalls[0]!;
    expect(call.address).toBe(FACTORY);
    expect(call.functionName).toBe("deploySpecificWalletProxy");
    expect(call.value).toBe(CREATION_FEE);
    expect(call.account).toBe(ACCOUNT);
    expect(call.args[0]).toBe(VAULT_ID);
    expect(call.args[1]).toBe(3n);
    expect(call.args[2]).toBe(ACCOUNT);
  });

  it("uses a non-zero-byte init payload so gas is not underpriced", async () => {
    const chain = fakeChain();

    await makeClient(chain).estimateCreationCost();

    const initPayload = chain.estimatedCalls[0]!.args[3];
    expect(initPayload).toContain("ff".repeat(STATEFUL_PUBLIC_KEY_BYTES));
  });

  it("builds a bundle whose embedded commitment recomputes", () => {
    const bundle = decodePlaceholderBundle();

    expect(bundle.publicKeyCommitment).toBe(publicKeyCommitment(bundle));
  });

  it("builds a bundle with the field widths the wallet requires", () => {
    const bundle = decodePlaceholderBundle();

    expect(byteLength(bundle.statefulPublicKey)).toBe(
      STATEFUL_PUBLIC_KEY_BYTES
    );
    expect(byteLength(bundle.publicKeyCommitment)).toBe(32);
    expect(byteLength(bundle.pkSeed)).toBe(32);
    expect(byteLength(bundle.hypertreeRoot)).toBe(32);
  });

  it("funds the sender in simulation so an empty account can be quoted", async () => {
    const chain = fakeChain();

    await expect(
      makeClient(chain).estimateCreationCost()
    ).resolves.toBeDefined();

    expect(chain.balanceReads()).toBe(0);
    const override = chain.estimatedCalls[0]!.stateOverride![0]!;
    expect(override.address).toBe(ACCOUNT);
    expect(override.balance).toBe(CREATION_FEE + 2_000_000_000n * 30_000_000n);
  });

  it("falls back to the legacy gas price when EIP-1559 estimation fails", async () => {
    const chain = fakeChain({ maxFeePerGas: undefined });

    const estimate = await makeClient(chain).estimateCreationCost();

    expect(estimate.gasPrice).toBe(7n);
    expect(estimate.expectedGasPrice).toBe(7n);
  });

  it("falls back to the legacy gas price when EIP-1559 returns no cap", async () => {
    const chain = fakeChain({ omitMaxFeePerGas: true });

    const estimate = await makeClient(chain).estimateCreationCost();

    expect(estimate.gasPrice).toBe(7n);
  });

  it("prefers an explicit fee override over the live gas price", async () => {
    const chain = fakeChain();

    const estimate = await makeClient(chain).estimateCreationCost(
      {},
      { maxFeePerGas: 99n }
    );

    expect(estimate.gasPrice).toBe(99n);
    expect(estimate.expectedGasPrice).toBe(99n);
  });

  it("prefers an explicit legacy gas price over the live gas price", async () => {
    const chain = fakeChain();

    const estimate = await makeClient(chain).estimateCreationCost(
      {},
      { gasPrice: 55n }
    );

    expect(estimate.gasPrice).toBe(55n);
    expect(estimate.expectedGasPrice).toBe(55n);
  });

  it("quotes one price on a chain with no base fee", async () => {
    const chain = fakeChain({ baseFeePerGas: null });

    const estimate = await makeClient(chain).estimateCreationCost();

    expect(estimate.expectedGasPrice).toBe(estimate.gasPrice);
  });

  it("rejects a provider that has switched chain", async () => {
    const chain = fakeChain();
    const client = new ShrincsFactoryClient({
      publicClient: chain.publicClient,
      walletClient: chain.walletClient,
      account: ACCOUNT,
      chainId: CHAIN_ID + 1,
      factoryAddress: FACTORY,
      walletImplementation: IMPLEMENTATION,
    });

    await expect(client.estimateCreationCost()).rejects.toBeInstanceOf(
      ChainChangedError
    );
  });

  it("rejects a vaultId that already has a wallet", async () => {
    const chain = fakeChain({
      wallets: {
        [VAULT_ID.toLowerCase()]: "0x00000000000000000000000000000000000000b1",
      },
    });

    await expect(
      makeClient(chain).estimateCreationCost({ vaultId: VAULT_ID })
    ).rejects.toBeInstanceOf(WalletAlreadyExistsError);
  });

  it("rejects an implementation that is not in the vetted set", async () => {
    const chain = fakeChain({ implementationCode: "0x" });

    await expect(
      makeClient(chain).estimateCreationCost()
    ).rejects.toBeInstanceOf(ImplementationNotVettedError);
  });
});
