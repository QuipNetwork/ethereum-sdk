// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  type PublicClient,
  type TransactionReceipt,
  type WalletClient,
  keccak256,
  toHex,
} from "viem";

import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";
import { ShrincsWalletClient } from "../shrincsWalletClient.js";

const WALLET = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const CHAIN_ID = 31337;
const MAX_SIG = 8;
const EXECUTE_FEE = 10_000_000n;
const TX_HASH =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const;
const ZERO32 = ("0x" + "00".repeat(32)) as Hex;
const seed = (s: string) => keccak256(toHex(new TextEncoder().encode(s)));

let keypair: ShrincsKeyPair;

beforeAll(async () => {
  const signer = await ShrincsSigner.create(new TextEncoder().encode("any master"));
  keypair = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
    maxSignatures: MAX_SIG,
  });
});

function walletRead(functionName: string): unknown {
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
      return MAX_SIG;
    case "isStatefulLeafUsed":
      return false;
    case "statefulLeafBitmapWord":
      return 0n;
    default:
      throw new Error(`unexpected wallet read: ${functionName}`);
  }
}

describe("ShrincsWalletClient fee-free writes", () => {
  it("markLeavesUsed submits with value 0n even when executeFee is non-zero", async () => {
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
      vaultId: seed("vault"),
      chainId: CHAIN_ID,
      account: ACCOUNT,
    });

    await client.markLeavesUsed(
      { leaves: [2] },
      { gas: 100_000n, skipPreflightChecks: true }
    );

    expect(writeValue).toBe(0n);
    expect(writeValue).not.toBe(EXECUTE_FEE);
  });
});
