// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  zeroAddress,
} from "viem";

import {
  type CreateShrincsWalletParams,
  ShrincsFactoryClient,
} from "../shrincsFactoryClient.js";
import { ShrincsSigner } from "../shrincsSigner.js";
import { v1Commitment } from "../addresses.js";
import { ChainChangedError, WalletAlreadyExistsError } from "../../errors.js";
import { applyGasMultiplier } from "../gas.js";
import { ImplementationNotVettedError } from "../errors.js";

const CHAIN_ID = 8453;
const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const FACTORY = "0x00000000000000000000000000000000000000f1" as Address;
const IMPLEMENTATION = "0x00000000000000000000000000000000000000e1" as Address;
const CREATION_FEE = 1_000_000_000_000_000n;
const DERIVATION_INDEX = 7;
const ERC1271_INDEX = DERIVATION_INDEX + 1000;
const MAX_SIGS = 40;

let signer: ShrincsSigner;
beforeAll(async () => {
  signer = await ShrincsSigner.create(
    new TextEncoder().encode("factory-estimate-test")
  );
});

function createParams(
  overrides: Partial<CreateShrincsWalletParams> = {}
): CreateShrincsWalletParams {
  return {
    signer,
    maxSignatures: MAX_SIGS,
    derivationIndex: DERIVATION_INDEX,
    erc1271: { derivationIndex: ERC1271_INDEX, maxSignatures: MAX_SIGS },
    ...overrides,
  };
}

interface EstimatedCall {
  address: Address;
  functionName: string;
  args: [Hex, bigint, Address, Hex];
  value: bigint;
  account: Address;
  stateOverride?: { address: Address; balance: bigint }[];
}

interface FakeChainState {
  /// Address the factory reports for ANY `wallets(salt)` lookup.
  existingWallet: Address;
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
    existingWallet: zeroAddress,
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
  const writtenCalls: EstimatedCall[] = [];
  let balanceReads = 0;

  const publicClient = {
    getChainId: async () => CHAIN_ID,
    getCode: async () => state.implementationCode,
    getBalance: async () => {
      balanceReads += 1;
      return 0n;
    },
    readContract: async ({ functionName }: { functionName: string }) => {
      switch (functionName) {
        case "wallets":
          return state.existingWallet;
        case "getVettedCodeIndex":
          return state.vettedIndex;
        case "deprecatedImpls":
          return false;
        case "creationFee":
          return CREATION_FEE;
        default:
          throw new Error(`unexpected read: ${functionName}`);
      }
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
    // Capture what the create path would broadcast, then refuse to send.
    writeContract: async (call: EstimatedCall) => {
      writtenCalls.push(call);
      throw new Error("test chain does not broadcast");
    },
  } as unknown as WalletClient;

  return {
    publicClient,
    walletClient,
    estimatedCalls,
    writtenCalls,
    balanceReads: () => balanceReads,
  };
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
  it("prices a deployment without broadcasting", async () => {
    const chain = fakeChain();

    const estimate = await makeClient(chain).estimateCreationCost(
      createParams()
    );

    expect(estimate.creationFee).toBe(CREATION_FEE);
    expect(estimate.gasPrice).toBe(2_000_000_000n);
    expect(estimate.gasUnits).toBe(applyGasMultiplier(400_000n, {}));
    expect(chain.writtenCalls).toHaveLength(0);
  });

  it("reports the likely cost alongside the ceiling", async () => {
    const chain = fakeChain();

    const estimate = await makeClient(chain).estimateCreationCost(
      createParams()
    );

    expect(estimate.expectedGasUnits).toBe(400_000n);
    expect(estimate.expectedGasPrice).toBe(1_400_000_000n + 1n);
    expect(estimate.expectedGasUnits).toBeLessThan(estimate.gasUnits);
    expect(estimate.expectedGasPrice).toBeLessThan(estimate.gasPrice);
    expect(chain.estimatedCalls).toHaveLength(1);
  });

  it("estimates byte-for-byte the deployment call the create path sends", async () => {
    const chain = fakeChain();
    const client = makeClient(chain);
    const mainKey = signer.recoverKeyPair(DERIVATION_INDEX, {
      maxSignatures: MAX_SIGS,
    });
    const erc1271Key = signer.recoverKeyPair(ERC1271_INDEX, {
      maxSignatures: MAX_SIGS,
    });
    const commitment = v1Commitment(
      mainKey.publicKeyCommitment,
      erc1271Key.publicKeyCommitment,
      ACCOUNT
    );

    await client.estimateCreationCost(createParams());
    await expect(
      client.createShrincsWallet(createParams(), {
        gas: 100_000n,
        skipPreflightChecks: true,
      })
    ).rejects.toThrow("test chain does not broadcast");

    const estimated = chain.estimatedCalls[0]!;
    const written = chain.writtenCalls[0]!;
    expect(estimated.address).toBe(FACTORY);
    expect(estimated.functionName).toBe("deploySpecificWalletProxy");
    expect(estimated.value).toBe(CREATION_FEE);
    expect(estimated.account).toBe(ACCOUNT);
    // V1: `deploySpecificWalletProxy(commitment, index, to, payload)`.
    expect(estimated.args[0]).toBe(commitment);
    expect(estimated.args[1]).toBe(3n);
    expect(estimated.args[2]).toBe(ACCOUNT);
    // Same key, same commitment, same init payload: the estimate and the
    // deployment are the same call byte-for-byte.
    expect(written.args).toEqual(estimated.args);
    expect(written.value).toBe(estimated.value);
  });

  it("funds the sender in simulation so an empty account can be quoted", async () => {
    const chain = fakeChain();

    await expect(
      makeClient(chain).estimateCreationCost(createParams())
    ).resolves.toBeDefined();

    expect(chain.balanceReads()).toBe(0);
    const override = chain.estimatedCalls[0]!.stateOverride![0]!;
    expect(override.address).toBe(ACCOUNT);
    expect(override.balance).toBe(CREATION_FEE + 2_000_000_000n * 30_000_000n);
  });

  it("falls back to the legacy gas price when EIP-1559 estimation fails", async () => {
    const chain = fakeChain({ maxFeePerGas: undefined });

    const estimate = await makeClient(chain).estimateCreationCost(
      createParams()
    );

    expect(estimate.gasPrice).toBe(7n);
    expect(estimate.expectedGasPrice).toBe(7n);
  });

  it("falls back to the legacy gas price when EIP-1559 returns no cap", async () => {
    const chain = fakeChain({ omitMaxFeePerGas: true });

    const estimate = await makeClient(chain).estimateCreationCost(
      createParams()
    );

    expect(estimate.gasPrice).toBe(7n);
  });

  it("prefers an explicit fee override over the live gas price", async () => {
    const chain = fakeChain();

    const estimate = await makeClient(chain).estimateCreationCost(
      createParams(),
      { maxFeePerGas: 99n }
    );

    expect(estimate.gasPrice).toBe(99n);
    expect(estimate.expectedGasPrice).toBe(99n);
  });

  it("prefers an explicit legacy gas price over the live gas price", async () => {
    const chain = fakeChain();

    const estimate = await makeClient(chain).estimateCreationCost(
      createParams(),
      { gasPrice: 55n }
    );

    expect(estimate.gasPrice).toBe(55n);
    expect(estimate.expectedGasPrice).toBe(55n);
  });

  it("quotes one price on a chain with no base fee", async () => {
    const chain = fakeChain({ baseFeePerGas: null });

    const estimate = await makeClient(chain).estimateCreationCost(
      createParams()
    );

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

    await expect(
      client.estimateCreationCost(createParams())
    ).rejects.toBeInstanceOf(ChainChangedError);
  });

  it("rejects a V1 identity that already has a wallet", async () => {
    const chain = fakeChain({
      existingWallet: "0x00000000000000000000000000000000000000b1",
    });

    await expect(
      makeClient(chain).estimateCreationCost(createParams())
    ).rejects.toBeInstanceOf(WalletAlreadyExistsError);
    expect(chain.estimatedCalls).toHaveLength(0);
  });

  it("rejects an implementation that is not in the vetted set", async () => {
    const chain = fakeChain({ implementationCode: "0x" });

    await expect(
      makeClient(chain).estimateCreationCost(createParams())
    ).rejects.toBeInstanceOf(ImplementationNotVettedError);
  });
});
