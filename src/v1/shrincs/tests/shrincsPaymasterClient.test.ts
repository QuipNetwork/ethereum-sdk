// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  keccak256,
  toBytes,
  toHex,
} from "viem";

import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import {
  GasEstimationError,
  ShrincsHdDerivationError,
  StatefulTreeSpentError,
} from "../errors.js";
import { ShrincsPaymasterClient } from "../shrincsPaymasterClient.js";
import { ShrincsSigner, type ShrincsKeyPair } from "../shrincsSigner.js";

const PAYMASTER = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const COMMITMENT = ("0x" + "11".repeat(32)) as Hex;
const CHAIN_ID = 31337;

describe("ShrincsPaymasterClient derivationIndex", () => {
  it("throws ShrincsHdDerivationError when derivationIndex is -1", async () => {
    const signer = await ShrincsSigner.create(
      new TextEncoder().encode("any master (hd seed padding)")
    );
    expect(
      () =>
        new ShrincsPaymasterClient({
          paymasterAddress: PAYMASTER,
          publicClient: {} as PublicClient,
          walletClient: {} as WalletClient,
          signer,
          commitment: COMMITMENT,
          derivationIndex: -1,
          chainId: CHAIN_ID,
          account: ACCOUNT,
        })
    ).toThrow(ShrincsHdDerivationError);
  });
});

describe("ShrincsPaymasterClient rotateStatefulKey spent-tree pre-flight", () => {
  const MAX_SIG = 8;
  const seed = (s: string) => keccak256(toHex(new TextEncoder().encode(s)));
  let keypair: ShrincsKeyPair;
  let freshKey: ShrincsKeyPair;

  beforeAll(async () => {
    const signer = await ShrincsSigner.create(
      new TextEncoder().encode("paymaster master (hd seed padding)")
    );
    keypair = signer.keygenFromSeedHex(seed("paymaster operator key seed"), {
      maxSignatures: MAX_SIG,
    });
    freshKey = signer.keygenFromSeedHex(seed("paymaster fresh key seed"), {
      maxSignatures: MAX_SIG,
    });
  });

  async function makeClient(): Promise<ShrincsPaymasterClient> {
    const signer = await ShrincsSigner.create(
      new TextEncoder().encode("paymaster master (hd seed padding)")
    );
    const publicClient = {
      getChainId: async () => CHAIN_ID,
      readContract: async ({ functionName }: { functionName: string }) => {
        if (functionName === "getShrincsVerifier") {
          return [keypair.publicKeyCommitment, HASH_SUITE_KECCAK_256, 0n, MAX_SIG, 0];
        }
        throw new Error(`unexpected paymaster read: ${functionName}`);
      },
    } as unknown as PublicClient;
    return new ShrincsPaymasterClient({
      paymasterAddress: PAYMASTER,
      publicClient,
      walletClient: { getAddresses: async () => [ACCOUNT] } as unknown as WalletClient,
      signer,
      keypair,
      commitment: keypair.publicKeyCommitment,
      chainId: CHAIN_ID,
      account: ACCOUNT,
    });
  }

  it("refuses the installed stateful tree", async () => {
    const client = await makeClient();
    await expect(
      client.rotateStatefulKey({ nextStatefulPublicKey: keypair.publicKey.statefulPublicKey })
    ).rejects.toThrow(StatefulTreeSpentError);
  });

  it("refuses the installed tree under a re-declared budget", async () => {
    const bytes = toBytes(keypair.publicKey.statefulPublicKey);
    bytes[67] = (bytes[67] + 1) & 0xff;
    const client = await makeClient();
    await expect(
      client.rotateStatefulKey({ nextStatefulPublicKey: toHex(bytes) })
    ).rejects.toThrow(StatefulTreeSpentError);
  });

  it("lets a fresh stateful tree through the pre-flight", async () => {
    const client = await makeClient();
    let caught: unknown;
    try {
      await client.rotateStatefulKey({
        nextStatefulPublicKey: freshKey.publicKey.statefulPublicKey,
      });
    } catch (e) {
      caught = e;
    }
    // Fails later at the unmocked send layer, never at the pre-flight.
    expect(caught).toBeDefined();
    expect(caught).toBeInstanceOf(GasEstimationError);
    expect(caught).not.toBeInstanceOf(StatefulTreeSpentError);
  });
});
