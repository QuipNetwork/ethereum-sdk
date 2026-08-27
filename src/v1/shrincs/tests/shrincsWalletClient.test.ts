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
  ShrincsHdDerivationError,
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
  const signer = await ShrincsSigner.create(new TextEncoder().encode("any master (hd seed padding)"));
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

describe("ShrincsWalletClient derivationIndex", () => {
  it("throws ShrincsHdDerivationError when derivationIndex is -1", () => {
    expect(
      () =>
        new ShrincsWalletClient({
          walletAddress: WALLET,
          publicClient: {} as PublicClient,
          walletClient: {} as WalletClient,
          keypair,
          commitment: seed("vault"),
          derivationIndex: -1,
          chainId: CHAIN_ID,
          account: ACCOUNT,
        })
    ).toThrow(ShrincsHdDerivationError);
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
