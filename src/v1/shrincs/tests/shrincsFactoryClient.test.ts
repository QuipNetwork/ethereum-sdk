// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  type PublicClient,
  type TransactionReceipt,
  type WalletClient,
  zeroAddress,
} from "viem";

import { TransactionRevertedError } from "../errors.js";
import { ShrincsFactoryClient } from "../shrincsFactoryClient.js";
import { type ShrincsSigner } from "../shrincsSigner.js";
import { type ShrincsPublicKey } from "../types.js";

const FACTORY = "0x00000000000000000000000000000000000000f1" as Address;
const IMPL = "0x00000000000000000000000000000000000000f2" as Address;
const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const CHAIN_ID = 31337;
const TX_HASH =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const;
const CODE = "0x60016000" as Hex;
const VAULT_ID =
  "0x1111111111111111111111111111111111111111111111111111111111111111" as Hex;
const ERC1271_COMMITMENT =
  "0x2222222222222222222222222222222222222222222222222222222222222222" as Hex;

function dummyPublicKey(): ShrincsPublicKey {
  const h32 = (n: string) => (`0x${n.repeat(32)}`) as Hex;
  return {
    publicKeyCommitment: h32("11"),
    pkSeed: h32("22"),
    hypertreeRoot: h32("33"),
    statefulPublicKey: h32("44"),
  };
}

function dummySigner(): ShrincsSigner {
  const publicKey = dummyPublicKey();
  return {
    recoverKeyPair: () => ({
      publicKey,
      publicKeyCommitment: publicKey.publicKeyCommitment,
    }),
  } as unknown as ShrincsSigner;
}

function factoryReads(functionName: string): unknown {
  switch (functionName) {
    case "wallets":
      return zeroAddress;
    case "getVettedCodeIndex":
      return 0n;
    case "deprecatedImpls":
      return false;
    case "creationFee":
      return 0n;
    default:
      throw new Error(`unexpected factory read: ${functionName}`);
  }
}

function makeFactory(opts: {
  receiptStatus: TransactionReceipt["status"];
}): ShrincsFactoryClient {
  const publicClient = {
    getChainId: async () => CHAIN_ID,
    getCode: async () => CODE,
    readContract: async ({ functionName }: { functionName: string }) =>
      factoryReads(functionName),
    waitForTransactionReceipt: async () =>
      ({
        status: opts.receiptStatus,
        transactionHash: TX_HASH,
        logs: [],
      }) as unknown as TransactionReceipt,
  } as unknown as PublicClient;
  const walletClient = {
    getAddresses: async () => [ACCOUNT],
    writeContract: async () => TX_HASH,
  } as unknown as WalletClient;
  return new ShrincsFactoryClient({
    publicClient,
    walletClient,
    account: ACCOUNT,
    chainId: CHAIN_ID,
    factoryAddress: FACTORY,
    walletImplementation: IMPL,
  });
}

describe("ShrincsFactoryClient.createShrincsWallet", () => {
  it("throws TransactionRevertedError when the deploy receipt status is reverted", async () => {
    const factory = makeFactory({ receiptStatus: "reverted" });
    await expect(
      factory.createShrincsWallet(
        {
          signer: dummySigner(),
          maxSignatures: 8,
          vaultId: VAULT_ID,
          erc1271: { commitment: ERC1271_COMMITMENT },
        },
        { gas: 100_000n, skipPreflightChecks: true }
      )
    ).rejects.toThrow(TransactionRevertedError);
  });
});
