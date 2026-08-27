// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  keccak256,
  toHex,
} from "viem";

import { ExecuteTargetHasNoCodeError } from "../errors.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";
import { ShrincsWalletClient } from "../shrincsWalletClient.js";

const WALLET = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const TARGET = "0x00000000000000000000000000000000000000c3" as Address;
const CHAIN_ID = 31337;
const seed = (s: string) => keccak256(toHex(new TextEncoder().encode(s)));

let keypair: ShrincsKeyPair;

beforeAll(async () => {
  const signer = await ShrincsSigner.create(new TextEncoder().encode("any master (hd seed padding)"));
  keypair = signer.keygenFromSeedHex(seed("execute guard key seed"), {
    maxSignatures: 8,
  });
});

// Build a client whose only relevant behavior is `getCode`. The guard runs
// before any wallet read, so a bare public client is enough.
function makeClient(code: Hex | undefined): ShrincsWalletClient {
  const publicClient = {
    getChainId: async () => CHAIN_ID,
    getCode: async () => code,
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

describe("execute target code guard", () => {
  it("assertExecuteTargetHasCode resolves when the target holds code", async () => {
    await expect(
      makeClient("0x6000").assertExecuteTargetHasCode(TARGET)
    ).resolves.toBeUndefined();
  });

  it("assertExecuteTargetHasCode throws for an empty ('0x') code result", async () => {
    await expect(
      makeClient("0x").assertExecuteTargetHasCode(TARGET)
    ).rejects.toBeInstanceOf(ExecuteTargetHasNoCodeError);
  });

  it("assertExecuteTargetHasCode throws when getCode returns undefined", async () => {
    await expect(
      makeClient(undefined).assertExecuteTargetHasCode(TARGET)
    ).rejects.toBeInstanceOf(ExecuteTargetHasNoCodeError);
  });

  it("the thrown error carries the offending target", async () => {
    await makeClient("0x").assertExecuteTargetHasCode(TARGET).catch((e: unknown) => {
      expect(e).toBeInstanceOf(ExecuteTargetHasNoCodeError);
      expect((e as ExecuteTargetHasNoCodeError).target).toBe(TARGET);
    });
  });

  it("execute rejects before consuming a leaf when calldata targets codeless code", async () => {
    // The guard runs before prepareStatefulOp, so a codeless target with
    // calldata throws without any wallet read or leaf consumption.
    await expect(
      makeClient("0x").execute({ target: TARGET, data: "0xabcdabcd" as Hex })
    ).rejects.toBeInstanceOf(ExecuteTargetHasNoCodeError);
  });
});
