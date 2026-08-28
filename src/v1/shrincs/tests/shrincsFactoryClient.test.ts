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
  zeroAddress,
} from "viem";

import { computeCreate3Address } from "../../addresses.js";
import {
  CommitmentMismatchError,
  ImplementationDeprecatedError,
  TransactionRevertedError,
} from "../errors.js";
import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import {
  getShrincsWalletAddress,
  v1Commitment,
} from "../addresses.js";
import { encodeInitPayload } from "../shrincsCodec.js";
import { ShrincsFactoryClient } from "../shrincsFactoryClient.js";
import {
  ShrincsSigner,
  type ShrincsKeyPair,
} from "../shrincsSigner.js";

// A real main keypair (the dummy signer below hands it back from `recoverKeyPair`).
let realKeypair: ShrincsKeyPair;
beforeAll(async () => {
  const signer = await ShrincsSigner.create(
    new TextEncoder().encode("factory-client-test")
  );
  realKeypair = signer.keygenFromSeedHex(
    keccak256(toHex("factory client seed")),
    { maxSignatures: 40 }
  );
});

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

function dummySigner(): ShrincsSigner {
  return {
    recoverKeyPair: () => realKeypair,
  } as unknown as ShrincsSigner;
}

function factoryReads(
  functionName: string,
  overrides: Record<string, unknown> = {}
): unknown {
  if (functionName in overrides) return overrides[functionName];
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

function makeFactory(
  opts: {
    receiptStatus?: TransactionReceipt["status"];
    reads?: Record<string, unknown>;
    captureWriteArgs?: (args: unknown[]) => void;
  } = {}
): ShrincsFactoryClient {
  const publicClient = {
    getChainId: async () => CHAIN_ID,
    getCode: async () => CODE,
    readContract: async ({ functionName }: { functionName: string }) =>
      factoryReads(functionName, opts.reads),
    waitForTransactionReceipt: async () =>
      ({
        status: opts.receiptStatus ?? "success",
        transactionHash: TX_HASH,
        logs: [],
      }) as unknown as TransactionReceipt,
  } as unknown as PublicClient;
  const walletClient = {
    getAddresses: async () => [ACCOUNT],
    writeContract: async (req: { args?: unknown[] }) => {
      if (opts.captureWriteArgs && req.args) opts.captureWriteArgs(req.args);
      return TX_HASH;
    },
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
  const createParams = {
    signer: dummySigner(),
    maxSignatures: 8,
    derivationIndex: 1,
    erc1271: { commitment: ERC1271_COMMITMENT },
  } as const;

  /**
   * Shared act for the reverted-receipt family: deploys with the standard
   * params against a mock whose receipt reverts, and asserts the typed error.
   */
  const expectRevertedDeploy = (factory: ReturnType<typeof makeFactory>) =>
    expect(
      factory.createShrincsWallet(createParams, {
        gas: 100_000n,
        skipPreflightChecks: true,
      })
    ).rejects.toThrow(TransactionRevertedError);

  it("throws TransactionRevertedError when the deploy receipt status is reverted", async () => {
    await expectRevertedDeploy(makeFactory({ receiptStatus: "reverted" }));
  });

  it("builds V1 deploy args with commitment from key material and no deploy authorization", async () => {
    let capturedArgs: unknown[] | undefined;
    const factory = makeFactory({
      receiptStatus: "reverted",
      captureWriteArgs: (args) => {
        capturedArgs = args;
      },
    });
    await expectRevertedDeploy(factory);

    expect(capturedArgs).toBeDefined();
    const args = capturedArgs as unknown[];
    const statefulC = realKeypair.publicKeyCommitment;
    const commitment = v1Commitment(statefulC, ERC1271_COMMITMENT, ACCOUNT);
    expect(args[0]).toBe(commitment);
    expect(args[1]).toBe(0n);
    expect(args[2]).toBe(ACCOUNT);
    expect(args[3]).toBe(
      encodeInitPayload({
        mainBundle: realKeypair.publicKey,
        erc1271Commitment: ERC1271_COMMITMENT,
      })
    );
    expect(args).toHaveLength(4);
  });
});

describe("getShrincsWalletAddress (CREATE3 predictor)", () => {
  it("equals computeCreate3Address(factory, v1Commitment)", () => {
    const statefulC = `0x${"11".repeat(32)}` as Hex;
    const statelessC = `0x${"22".repeat(32)}` as Hex;
    expect(
      getShrincsWalletAddress(FACTORY, statefulC, statelessC, ACCOUNT)
    ).toBe(
      computeCreate3Address(
        FACTORY,
        v1Commitment(statefulC, statelessC, ACCOUNT)
      )
    );
  });
});

type ResolveImplementationIndex = () => Promise<bigint>;

function resolveImplementationIndex(
  factory: ShrincsFactoryClient
): Promise<bigint> {
  const fn = (
    factory as unknown as {
      resolveImplementationIndex: ResolveImplementationIndex;
    }
  ).resolveImplementationIndex;
  return fn.call(factory);
}

describe("ShrincsFactoryClient.resolveImplementationIndex", () => {
  it("throws ImplementationDeprecatedError when the resolved implementation is deprecated", async () => {
    const factory = makeFactory({ reads: { deprecatedImpls: true } });
    await expect(resolveImplementationIndex(factory)).rejects.toThrow(
      ImplementationDeprecatedError
    );
  });
});

describe("ShrincsFactoryClient.openShrincsWallet", () => {
  it("throws CommitmentMismatchError when the keypair does not match the installed commitment", async () => {
    const walletAddress =
      "0x00000000000000000000000000000000000000aa" as Address;
    const onChainCommitment = (`0x${"aa".repeat(32)}`) as Hex;
    const suppliedCommitment = (`0x${"bb".repeat(32)}`) as Hex;
    const walletReads: Record<string, unknown> = {
      owner: ACCOUNT,
      version: 1n,
      getExecuteFee: 0n,
      getShrincsPublicKeyCommitment: onChainCommitment,
      getErc1271Commitment: (`0x${"00".repeat(32)}`) as Hex,
      getHashSuite: HASH_SUITE_KECCAK_256,
      getErc1271HashSuite: HASH_SUITE_KECCAK_256,
      keyVersion: 0n,
      actionNonce: 0n,
      maxSignatures: 8,
      statefulLeavesUsed: 0,
      remainingStatefulSignatures: 8,
    };
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
          result: walletReads[c.functionName],
        })),
      readContract: async ({ functionName }: { functionName: string }) => {
        if (functionName === "wallets") return walletAddress;
        if (functionName in walletReads) return walletReads[functionName];
        throw new Error(`unexpected factory read: ${functionName}`);
      },
    } as unknown as PublicClient;
    const factory = new ShrincsFactoryClient({
      publicClient,
      walletClient: { getAddresses: async () => [ACCOUNT] } as unknown as WalletClient,
      account: ACCOUNT,
      chainId: CHAIN_ID,
      factoryAddress: FACTORY,
      walletImplementation: IMPL,
    });
    const keypair = {
      publicKeyCommitment: suppliedCommitment,
    } as unknown as ShrincsKeyPair;

    await expect(
      factory.openShrincsWallet({ commitment: VAULT_ID, keypair })
    ).rejects.toThrow(CommitmentMismatchError);
  });
});
