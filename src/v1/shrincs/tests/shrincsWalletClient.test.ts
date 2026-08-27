// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  type LocalAccount,
  type PublicClient,
  type TransactionReceipt,
  type WalletClient,
  keccak256,
  toHex,
} from "viem";

import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import {
  OwnerMismatchError,
  ZeroAddressOwnerError,
  ZeroErc1271CommitmentError,
} from "../errors.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";
import { ShrincsWalletClient } from "../shrincsWalletClient.js";
import { type PackedUserOperation } from "../../userOpCodec.js";

const WALLET = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const CHAIN_ID = 31337;
const SIGNING_BUDGET = 8;
const MAX_SIG = SIGNING_BUDGET;
const EXECUTE_FEE = 10_000_000n;
const TX_HASH =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const;
const ZERO32 = ("0x" + "00".repeat(32)) as Hex;
const ZERO_ADDRESS =
  "0x0000000000000000000000000000000000000000" as Address;
const WRONG_OWNER = "0x00000000000000000000000000000000000000b2" as Address;
const ENTRY_POINT = "0x0000000071727De22E5E9d8BAf0edAc6f37da032" as Address;
const seed = (s: string) => keccak256(toHex(new TextEncoder().encode(s)));

let keypair: ShrincsKeyPair;

beforeAll(async () => {
  const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
  keypair = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
    maxSignatures: MAX_SIG,
  });
});

function walletRead(
  functionName: string,
  overrides: Record<string, unknown> = {}
): unknown {
  if (Object.prototype.hasOwnProperty.call(overrides, functionName)) {
    return overrides[functionName];
  }
  switch (functionName) {
    case "owner":
      return ACCOUNT;
    case "version":
      return 1n;
    case "getExecuteFee":
      return EXECUTE_FEE;
    case "getShrincsPublicKeyCommitment":
      return keypair.publicKeyCommitment;
    case "getErc1271Commitment":
      return ZERO32;
    case "getHashSuite":
      return HASH_SUITE_KECCAK_256;
    case "getErc1271HashSuite":
      return HASH_SUITE_KECCAK_256;
    case "keyVersion":
      return 0n;
    case "actionNonce":
      return 0n;
    case "maxSignatures":
      return MAX_SIG;
    case "statefulLeavesUsed":
      return 0;
    case "remainingStatefulSignatures":
      return SIGNING_BUDGET;
    case "isStatefulLeafUsed":
      return false;
    default:
      throw new Error(`unexpected wallet read: ${functionName}`);
  }
}

describe("ShrincsWalletClient fee-free writes", () => {
  function makeFeeFreeWriteClient(): {
    client: ShrincsWalletClient;
    capturedValue: () => bigint | undefined;
  } {
    let writeValue: bigint | undefined;
    const publicClient = {
      getChainId: async () => CHAIN_ID,
      getCode: async () => "0x6000" as Hex,
      multicall: async ({
        contracts,
      }: {
        contracts: readonly { functionName: string }[];
      }) =>
        contracts.map((c) => ({
          status: "success" as const,
          result: walletRead(c.functionName),
        })),
      readContract: async ({ functionName }: { functionName: string }) =>
        walletRead(functionName),
      waitForTransactionReceipt: async () =>
        ({
          status: "success",
          transactionHash: TX_HASH,
        }) as unknown as TransactionReceipt,
    } as unknown as PublicClient;
    const walletClient = {
      getAddresses: async () => [ACCOUNT],
      writeContract: async (params: { value?: bigint }) => {
        writeValue = params.value;
        return TX_HASH;
      },
    } as unknown as WalletClient;
    const client = new ShrincsWalletClient({
      walletAddress: WALLET,
      publicClient,
      walletClient,
      keypair,
      commitment: seed("vault"),
      chainId: CHAIN_ID,
      account: ACCOUNT,
    });
    return { client, capturedValue: () => writeValue };
  }

  const feeFreeOpts = { gas: 100_000n, skipPreflightChecks: true } as const;

  it("markLeavesUsed submits with value 0n even when executeFee is non-zero", async () => {
    const { client, capturedValue } = makeFeeFreeWriteClient();

    await client.markLeavesUsed({ leaves: [2] }, feeFreeOpts);

    expect(capturedValue()).toBe(0n);
    expect(capturedValue()).not.toBe(EXECUTE_FEE);
  });

  it("withdrawDepositTo submits with value 0n even when executeFee is non-zero", async () => {
    const { client, capturedValue } = makeFeeFreeWriteClient();

    await client.withdrawDepositTo({ to: ACCOUNT, amount: 1n }, feeFreeOpts);

    expect(capturedValue()).toBe(0n);
    expect(capturedValue()).not.toBe(EXECUTE_FEE);
  });

  it("upgradeToAndCall submits with value 0n even when executeFee is non-zero", async () => {
    const { client, capturedValue } = makeFeeFreeWriteClient();
    const newImplementation =
      "0x00000000000000000000000000000000000000c3" as Address;

    await client.upgradeToAndCall({ newImplementation }, feeFreeOpts);

    expect(capturedValue()).toBe(0n);
    expect(capturedValue()).not.toBe(EXECUTE_FEE);
  });
});

function makeWalletClient(
  overrides: Record<string, unknown> = {}
): ShrincsWalletClient {
  const publicClient = {
    getChainId: async () => CHAIN_ID,
    getCode: async () => "0x6000" as Hex,
    multicall: async ({
      contracts,
    }: {
      contracts: readonly { functionName: string }[];
    }) =>
      contracts.map((c) => ({
        status: "success" as const,
        result: walletRead(c.functionName, overrides),
      })),
    readContract: async ({ functionName }: { functionName: string }) =>
      walletRead(functionName, overrides),
  } as unknown as PublicClient;
  const walletClient = {
    getAddresses: async () => [ACCOUNT],
  } as unknown as WalletClient;
  return new ShrincsWalletClient({
    walletAddress: WALLET,
    publicClient,
    walletClient,
    keypair,
    commitment: seed("vault"),
    chainId: CHAIN_ID,
    account: ACCOUNT,
  });
}

function localAccount(address: Address): LocalAccount {
  return { address } as LocalAccount;
}

describe("ShrincsWalletClient owner mismatch", () => {
  it("signErc1271 throws OwnerMismatchError when the owner is non-zero but wrong", async () => {
    const client = makeWalletClient({
      getErc1271Commitment: keypair.publicKeyCommitment,
    });
    const err = await client
      .signErc1271({
        hash: ZERO32,
        erc1271KeyPair: keypair,
        owner: localAccount(WRONG_OWNER),
      })
      .then(
        () => {
          throw new Error("expected OwnerMismatchError");
        },
        (e: unknown) => e
      );
    expect(err).toBeInstanceOf(OwnerMismatchError);
    expect((err as OwnerMismatchError).expected).toBe(ACCOUNT);
    expect((err as OwnerMismatchError).actual).toBe(WRONG_OWNER);
  });

  it("signErc1271 throws ZeroAddressOwnerError when the owner address is zero", async () => {
    const client = makeWalletClient({
      getErc1271Commitment: keypair.publicKeyCommitment,
    });
    await expect(
      client.signErc1271({
        hash: ZERO32,
        erc1271KeyPair: keypair,
        owner: localAccount(ZERO_ADDRESS),
      })
    ).rejects.toThrow(ZeroAddressOwnerError);
  });

  it("signExecuteUserOp throws OwnerMismatchError when the owner is non-zero but wrong", async () => {
    const client = makeWalletClient();
    await expect(
      client.signExecuteUserOp({
        userOp: {} as PackedUserOperation,
        entryPoint: ENTRY_POINT,
        owner: localAccount(WRONG_OWNER),
      })
    ).rejects.toThrow(OwnerMismatchError);
  });
});

describe("ShrincsWalletClient setErc1271Key", () => {
  it("throws ZeroErc1271CommitmentError for the 32-byte zero word", async () => {
    const client = makeWalletClient();
    await expect(
      client.setErc1271Key({ newCommitment: ZERO32 })
    ).rejects.toThrow(ZeroErc1271CommitmentError);
  });

  it("throws ZeroErc1271CommitmentError for an empty commitment", async () => {
    const client = makeWalletClient();
    await expect(
      client.setErc1271Key({ newCommitment: "" as Hex })
    ).rejects.toThrow(ZeroErc1271CommitmentError);
  });
});

describe("ShrincsWalletClient prepareExecute signs once", () => {
  interface CapturedCall {
    functionName: string;
    args: readonly unknown[];
    value?: bigint;
  }

  /// A keypair whose `signStatefulActionAt` is counted and delegated unchanged.
  function countingKeypair(): {
    keypair: ShrincsKeyPair;
    signs: () => number;
    leaves: () => number[];
  } {
    let signs = 0;
    const leaves: number[] = [];
    const spy = Object.create(keypair) as ShrincsKeyPair;
    spy.signStatefulActionAt = (ctx, leaf) => {
      signs += 1;
      leaves.push(leaf);
      return keypair.signStatefulActionAt(ctx, leaf);
    };
    return { keypair: spy, signs: () => signs, leaves: () => leaves };
  }

  function makePrepareClient() {
    const counted = countingKeypair();
    const estimated: CapturedCall[] = [];
    const written: CapturedCall[] = [];
    const publicClient = {
      getChainId: async () => CHAIN_ID,
      getCode: async () => "0x6000" as Hex,
      multicall: async ({
        contracts,
      }: {
        contracts: readonly { functionName: string }[];
      }) =>
        contracts.map((c) => ({
          status: "success" as const,
          result: walletRead(c.functionName),
        })),
      readContract: async ({ functionName }: { functionName: string }) =>
        walletRead(functionName),
      estimateContractGas: async (call: CapturedCall) => {
        estimated.push(call);
        return 250_000n;
      },
      waitForTransactionReceipt: async () =>
        ({
          status: "success",
          transactionHash: TX_HASH,
        }) as unknown as TransactionReceipt,
    } as unknown as PublicClient;
    const walletClient = {
      getAddresses: async () => [ACCOUNT],
      writeContract: async (call: CapturedCall) => {
        written.push(call);
        return TX_HASH;
      },
    } as unknown as WalletClient;
    const client = new ShrincsWalletClient({
      walletAddress: WALLET,
      publicClient,
      walletClient,
      keypair: counted.keypair,
      commitment: seed("vault"),
      chainId: CHAIN_ID,
      account: ACCOUNT,
    });
    return { client, estimated, written, ...counted };
  }

  // Pinned fee => no fee RPCs; no `gas` => the estimate really simulates.
  const opts = { skipPreflightChecks: true, maxFeePerGas: 1n } as const;
  const transfer = { target: WRONG_OWNER, value: 1n } as const;

  it("signs exactly once across prepare + send, and sends the estimated bytes", async () => {
    const { client, estimated, written, signs, leaves } = makePrepareClient();

    const prepared = await client.prepareExecute(transfer, opts);
    expect(signs()).toBe(1);
    expect(prepared.leaf).toBe(leaves()[0]);
    // Lowest free leaf: under V1 nothing is reserved ahead of execute leaves.
    expect(prepared.leaf).toBe(1);
    expect(estimated).toHaveLength(1);
    expect(written).toHaveLength(0);

    await prepared.send();
    // `send()` re-simulates for gas but never re-signs.
    expect(signs()).toBe(1);
    expect(written).toHaveLength(1);
    expect(written[0]!.functionName).toBe("execute");
    expect(written[0]!.args).toEqual(estimated[0]!.args);
    expect(written[0]!.value).toBe(estimated[0]!.value);
  });

  it("refuses a second send without signing again", async () => {
    const { client, written, signs } = makePrepareClient();

    const prepared = await client.prepareExecute(transfer, opts);
    await prepared.send();
    await expect(prepared.send()).rejects.toThrow("already sent");

    expect(signs()).toBe(1);
    expect(written).toHaveLength(1);
  });

  it("hands every prepare and execute on one client a distinct leaf", async () => {
    const { client, signs, leaves } = makePrepareClient();

    const first = await client.prepareExecute(transfer, opts);
    const second = await client.prepareExecute(
      { ...transfer, value: 2n },
      opts
    );
    // A plain execute after two un-sent prepares must not reuse either leaf,
    // even though the on-chain bitmap (mocked) still reports both as free.
    await client.execute({ ...transfer, value: 3n }, { ...opts, gas: 100_000n });

    expect(signs()).toBe(3);
    const used = leaves();
    expect(used[0]).toBe(first.leaf);
    expect(used[1]).toBe(second.leaf);
    // Sequential from leaf 1: no deploy reservation under V1, and the in-memory
    // store keeps un-sent prepares from being reused.
    expect(used).toEqual([1, 2, 3]);
  });
});
