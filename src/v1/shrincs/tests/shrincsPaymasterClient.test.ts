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
  sliceHex,
} from "viem";

import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import {
  GasEstimationError,
  InvalidSponsorshipWindowError,
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

describe("ShrincsPaymasterClient sponsorUserOp validity window", () => {
  const MAX_SIG = 8;
  const NOW = 1_700_000_000;
  const seed = (s: string) => keccak256(toHex(new TextEncoder().encode(s)));
  let keypair: ShrincsKeyPair;
  let signer: ShrincsSigner;

  beforeAll(async () => {
    signer = await ShrincsSigner.create(new TextEncoder().encode("paymaster master (hd seed padding)"));
    keypair = signer.keygenFromSeedHex(seed("paymaster window key seed"), { maxSignatures: MAX_SIG });
  });

  function makeClient(): { client: ShrincsPaymasterClient; reads: () => number } {
    let reads = 0;
    const publicClient = {
      getChainId: async () => CHAIN_ID,
      readContract: async ({ functionName }: { functionName: string }) => {
        reads += 1;
        if (functionName === "getShrincsVerifier") {
          return [keypair.publicKeyCommitment, HASH_SUITE_KECCAK_256, 0n, MAX_SIG, 0];
        }
        throw new Error(`unexpected paymaster read: ${functionName}`);
      },
    } as unknown as PublicClient;
    const client = new ShrincsPaymasterClient({
      paymasterAddress: PAYMASTER,
      publicClient,
      walletClient: { getAddresses: async () => [ACCOUNT] } as unknown as WalletClient,
      signer,
      keypair,
      commitment: keypair.publicKeyCommitment,
      chainId: CHAIN_ID,
      account: ACCOUNT,
    });
    return { client, reads: () => reads };
  }

  const userOp = {
    sender: "0x00000000000000000000000000000000000000d1" as Address,
    nonce: 0n,
    initCode: "0x" as Hex,
    callData: "0x" as Hex,
    accountGasLimits: ("0x" + "00".repeat(32)) as Hex,
    preVerificationGas: 0n,
    gasFees: ("0x" + "00".repeat(32)) as Hex,
    paymasterAndData: "0x" as Hex,
    signature: "0x" as Hex,
  };

  it("defaults to a 15-minute window and reports it", async () => {
    const { client } = makeClient();
    const r = await client.sponsorUserOp({ userOp, now: NOW, leaf: 1 });
    expect(r.validUntil).toBe(NOW + 15 * 60);
    expect(r.validAfter).toBe(0);
    expect(BigInt(sliceHex(r.paymasterAndData, 52, 58))).toBe(BigInt(NOW + 15 * 60));
  });

  it("honours overrides and the explicit unbounded opt-in", async () => {
    const { client } = makeClient();
    const custom = await client.sponsorUserOp({ userOp, now: NOW, validitySeconds: 120, validAfter: NOW, leaf: 2 });
    expect(custom.validUntil).toBe(NOW + 120);
    expect(custom.validAfter).toBe(NOW);
    const unbounded = await client.sponsorUserOp({ userOp, now: NOW, validUntil: 0, leaf: 3 });
    expect(unbounded.validUntil).toBe(0);
    expect(BigInt(sliceHex(unbounded.paymasterAndData, 52, 58))).toBe(0n);
  });

  it("rejects a malformed window before reading the verifier or reserving a leaf", async () => {
    const { client, reads } = makeClient();
    await expect(
      client.sponsorUserOp({ userOp, now: NOW, validUntil: NOW - 1, leaf: 4 })
    ).rejects.toThrow(InvalidSponsorshipWindowError);
    expect(reads()).toBe(0);
    // The leaf was not reserved: an explicit re-pick of it still works.
    const r = await client.sponsorUserOp({ userOp, now: NOW, leaf: 4 });
    expect(r.leaf).toBe(4);
  });
});
