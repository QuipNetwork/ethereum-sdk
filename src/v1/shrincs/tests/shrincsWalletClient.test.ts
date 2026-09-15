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
  toBytes,
} from "viem";

import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import {
  AuthLeafInTargetsError,
  GasEstimationError,
  OwnerMismatchError,
  ShrincsHdDerivationError,
  ZeroAddressOwnerError,
  StatefulTreeSpentError,
  StatelessTreeSpentError,
  UnsupportedByWalletVersionError,
} from "../errors.js";
import { SHRINCS_WALLET_BETA2_IMPLEMENTATION } from "../addresses.js";
import { encodeInitPayload } from "../shrincsCodec.js";
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
let freshKey: ShrincsKeyPair;
/// Second never-installed bundle, so a migrate payload can carry a fresh main
/// AND a fresh, distinct ERC-1271 bundle.
let freshErc1271Key: ShrincsKeyPair;
let signer: ShrincsSigner;

// A non-beta.2 implementation address, padded to a full ERC-1967 slot word, so
// the version resolver reads these mock wallets as the `latest` generation
// (whose ABI matches the current-getter names `walletRead` returns).
const LATEST_IMPL_SLOT =
  "0x00000000000000000000000000000000000000000000000000000000c0de1a7e" as Hex;

beforeAll(async () => {
  signer = await ShrincsSigner.create(new TextEncoder().encode("any master (hd seed padding)"));
  keypair = signer.keygenFromSeedHex(seed("shrincs wallet main key seed"), {
    maxSignatures: MAX_SIG,
  });
  freshKey = signer.keygenFromSeedHex(seed("shrincs wallet fresh key seed"), {
    maxSignatures: MAX_SIG,
  });
  freshErc1271Key = signer.keygenFromSeedHex(seed("shrincs wallet fresh erc1271 key seed"), {
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
    case "getErc1271PublicKeyCommitment":
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
    case "statefulLeafBitmapWord":
      return 0n;
    case "verifyUpgrade":
      return undefined; // view probe: resolves (no revert) in these mocks
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
      getStorageAt: async () => LATEST_IMPL_SLOT,
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
      // A signer is required to build the verifyUpgrade probe vector.
      signer,
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
    getStorageAt: async () => LATEST_IMPL_SLOT,
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
    signer,
    keypair,
    commitment: seed("vault"),
    chainId: CHAIN_ID,
    account: ACCOUNT,
  });
}

function localAccount(address: Address): LocalAccount {
  return { address } as LocalAccount;
}

describe("ShrincsWalletClient version gating", () => {
  // A client whose wallet resolves to the frozen V1.0.1-beta.2 generation
  // (getStorageAt returns the beta.2 implementation in the ERC-1967 slot).
  function makeBeta2Client(): ShrincsWalletClient {
    const beta2Slot =
      `0x${SHRINCS_WALLET_BETA2_IMPLEMENTATION.slice(2).toLowerCase().padStart(64, "0")}` as Hex;
    const publicClient = {
      getChainId: async () => CHAIN_ID,
      getCode: async () => "0x6000" as Hex,
      getStorageAt: async () => beta2Slot,
    } as unknown as PublicClient;
    const walletClient = {
      getAddresses: async () => [ACCOUNT],
    } as unknown as WalletClient;
    return new ShrincsWalletClient({
      walletAddress: WALLET,
      publicClient,
      walletClient,
      signer,
      keypair,
      commitment: seed("vault"),
      chainId: CHAIN_ID,
      account: ACCOUNT,
    });
  }

  it("resolveVersion recognizes a beta.2 wallet", async () => {
    const version = await makeBeta2Client().resolveVersion();
    expect(version.id).toBe("v1.0.1-beta.2");
  });

  it("setErc1271Key throws UnsupportedByWalletVersionError on a beta.2 wallet", async () => {
    const client = makeBeta2Client();
    const err = await client
      .setErc1271Key({ newErc1271Key: keypair.publicKey })
      .then(
        () => {
          throw new Error("expected UnsupportedByWalletVersionError");
        },
        (e: unknown) => e
      );
    expect(err).toBeInstanceOf(UnsupportedByWalletVersionError);
    expect((err as UnsupportedByWalletVersionError).operation).toBe(
      "setErc1271Key"
    );
    expect((err as UnsupportedByWalletVersionError).versionLabel).toBe(
      "V1.0.1-beta.2"
    );
  });
});

describe("ShrincsWalletClient owner mismatch", () => {
  it("signErc1271 throws OwnerMismatchError when the owner is non-zero but wrong", async () => {
    const client = makeWalletClient({
      getErc1271PublicKeyCommitment: keypair.publicKeyCommitment,
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
      getErc1271PublicKeyCommitment: keypair.publicKeyCommitment,
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

describe("ShrincsWalletClient spent-tree pre-flights", () => {
  const NEW_OWNER = "0x00000000000000000000000000000000000000c3" as Address;

  /// The installed stateful key with its trailing `maxSignatures` re-declared:
  /// a different commitment, the same tree.
  function rebudgeted(statefulPublicKey: Hex): Hex {
    const bytes = toBytes(statefulPublicKey);
    bytes[67] = (bytes[67] + 1) & 0xff;
    return toHex(bytes);
  }

  /// Fresh stateful subkey grafted onto the INSTALLED stateless half.
  const carriedStateless = () => ({
    ...freshKey.publicKey,
    pkSeed: keypair.publicKey.pkSeed,
    hypertreeRoot: keypair.publicKey.hypertreeRoot,
  });

  /// Runs `fn` and asserts it did NOT fail the spent-tree pre-flight (it is
  /// expected to fail later, at the unmocked send layer).
  async function passesPreflight(fn: () => Promise<unknown>): Promise<void> {
    let caught: unknown;
    try {
      await fn();
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeDefined();
    expect(caught).toBeInstanceOf(GasEstimationError);
    expect(caught).not.toBeInstanceOf(StatefulTreeSpentError);
    expect(caught).not.toBeInstanceOf(StatelessTreeSpentError);
  }

  it("rotateKey refuses the installed stateful tree", async () => {
    const client = makeWalletClient();
    await expect(
      client.rotateKey({ nextStatefulPublicKey: keypair.publicKey.statefulPublicKey })
    ).rejects.toThrow(StatefulTreeSpentError);
  });

  it("rotateKey refuses the installed tree under a re-declared budget", async () => {
    const client = makeWalletClient();
    await expect(
      client.rotateKey({ nextStatefulPublicKey: rebudgeted(keypair.publicKey.statefulPublicKey) })
    ).rejects.toThrow(StatefulTreeSpentError);
  });

  it("rotateKey lets a fresh stateful tree through", async () => {
    const client = makeWalletClient();
    await passesPreflight(() =>
      client.rotateKey({ nextStatefulPublicKey: freshKey.publicKey.statefulPublicKey })
    );
  });

  it("rotateKey rejection reserves no leaf (the next call still picks leaf 1)", async () => {
    const client = makeWalletClient();
    await expect(
      client.rotateKey({ nextStatefulPublicKey: keypair.publicKey.statefulPublicKey })
    ).rejects.toThrow(StatefulTreeSpentError);
    // markLeavesUsed's own guard forbids authorizing from inside the target set:
    // if leaf 1 had been reserved by the rejected rotation, the auto-pick would
    // move to 2 and this would no longer be the in-set collision it asserts.
    await expect(client.markLeavesUsed({ leaves: [1] }, { leaf: 1 })).rejects.toThrow(
      AuthLeafInTargetsError
    );
  });

  it("recoverWallet refuses the installed bundle", async () => {
    const client = makeWalletClient();
    await expect(client.recoverWallet({ nextKey: keypair.publicKey })).rejects.toThrow(
      StatefulTreeSpentError
    );
  });

  it("recoverWallet refuses a carried-forward stateless tree", async () => {
    const client = makeWalletClient();
    await expect(client.recoverWallet({ nextKey: carriedStateless() })).rejects.toThrow(
      StatelessTreeSpentError
    );
  });

  it("recoverWallet lets a fresh bundle through", async () => {
    const client = makeWalletClient();
    await passesPreflight(() => client.recoverWallet({ nextKey: freshKey.publicKey }));
  });

  it("transferOwnership refuses the installed bundle", async () => {
    const client = makeWalletClient();
    await expect(
      client.transferOwnership({ nextKey: keypair.publicKey, newOwner: NEW_OWNER })
    ).rejects.toThrow(StatefulTreeSpentError);
  });

  it("transferOwnership refuses a carried-forward stateless tree", async () => {
    const client = makeWalletClient();
    await expect(
      client.transferOwnership({ nextKey: carriedStateless(), newOwner: NEW_OWNER })
    ).rejects.toThrow(StatelessTreeSpentError);
  });

  it("transferOwnership lets a fresh bundle through", async () => {
    const client = makeWalletClient();
    await passesPreflight(() =>
      client.transferOwnership({ nextKey: freshKey.publicKey, newOwner: NEW_OWNER })
    );
  });

  it("setErc1271Key refuses a bundle sharing the installed main stateful tree", async () => {
    const client = makeWalletClient();
    await expect(
      client.setErc1271Key({
        newErc1271Key: {
          ...freshKey.publicKey,
          statefulPublicKey: keypair.publicKey.statefulPublicKey,
        },
      })
    ).rejects.toThrow(StatefulTreeSpentError);
  });

  it("setErc1271Key refuses a bundle carrying the installed main stateless root", async () => {
    const client = makeWalletClient();
    await expect(
      client.setErc1271Key({ newErc1271Key: carriedStateless() })
    ).rejects.toThrow(StatelessTreeSpentError);
  });

  it("setErc1271Key refuses re-installing the installed 1271 bundle", async () => {
    const client = makeWalletClient({
      getErc1271PublicKeyCommitment: freshKey.publicKeyCommitment,
    });
    await expect(
      client.setErc1271Key({ newErc1271Key: freshKey.publicKey })
    ).rejects.toThrow(StatefulTreeSpentError);
  });

  it("setErc1271Key lets a fresh bundle through", async () => {
    const client = makeWalletClient();
    await passesPreflight(() =>
      client.setErc1271Key({ newErc1271Key: freshKey.publicKey })
    );
  });

  it("upgradeToAndCall migrate refuses a 1271 bundle sharing a tree with the payload's main bundle", async () => {
    const client = makeWalletClient();
    await expect(
      client.upgradeToAndCall({
        newImplementation: WRONG_OWNER,
        shouldMigrate: true,
        migratorPayload: encodeInitPayload({
          mainBundle: freshKey.publicKey,
          erc1271Bundle: freshKey.publicKey,
        }),
      })
    ).rejects.toThrow(StatefulTreeSpentError);
  });

  it("upgradeToAndCall migrate refuses re-installing the installed 1271 bundle", async () => {
    const client = makeWalletClient({
      getErc1271PublicKeyCommitment: freshKey.publicKeyCommitment,
    });
    await expect(
      client.upgradeToAndCall({
        newImplementation: WRONG_OWNER,
        shouldMigrate: true,
        migratorPayload: encodeInitPayload({
          mainBundle: freshErc1271Key.publicKey,
          erc1271Bundle: freshKey.publicKey,
        }),
      })
    ).rejects.toThrow(StatefulTreeSpentError);
  });

  it("transferOwnership rejection reserves no leaf (the next call still picks leaf 1)", async () => {
    const client = makeWalletClient();
    await expect(
      client.transferOwnership({ nextKey: keypair.publicKey, newOwner: NEW_OWNER })
    ).rejects.toThrow(StatefulTreeSpentError);
    // markLeavesUsed's own guard forbids authorizing from inside the target set:
    // if leaf 1 had been reserved by the rejected handover, the auto-pick would
    // move to 2 and this would no longer be the in-set collision it asserts.
    await expect(client.markLeavesUsed({ leaves: [1] }, { leaf: 1 })).rejects.toThrow(
      AuthLeafInTargetsError
    );
  });

  it("upgradeToAndCall migrate refuses the installed bundle before reserving a leaf", async () => {
    const client = makeWalletClient();
    const migratorPayload = encodeInitPayload({
      mainBundle: keypair.publicKey,
      erc1271Bundle: freshKey.publicKey,
    });
    await expect(
      client.upgradeToAndCall({
        newImplementation: WRONG_OWNER,
        shouldMigrate: true,
        migratorPayload,
      })
    ).rejects.toThrow(StatefulTreeSpentError);
    await expect(client.markLeavesUsed({ leaves: [1] }, { leaf: 1 })).rejects.toThrow(
      AuthLeafInTargetsError
    );
  });

  it("upgradeToAndCall migrate lets a fresh-bundle payload through the pre-flight", async () => {
    const client = makeWalletClient();
    await passesPreflight(() =>
      client.upgradeToAndCall({
        newImplementation: WRONG_OWNER,
        shouldMigrate: true,
        migratorPayload: encodeInitPayload({
          mainBundle: freshKey.publicKey,
          erc1271Bundle: freshErc1271Key.publicKey,
        }),
      })
    );
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
      getStorageAt: async () => LATEST_IMPL_SLOT,
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
