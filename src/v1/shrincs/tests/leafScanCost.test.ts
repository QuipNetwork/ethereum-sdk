// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Cost characterisation for the lowest-unused-leaf scan. The scan is on the
/// hot path of every sponsorship and every wallet signature, and its cost must
/// not grow with the size of the key's signature budget: a 2^20-leaf tree must
/// not cost 4096 bitmap-word reads per signature. These tests pin the round
/// trips, the words read, and the decode work so a regression to a
/// whole-bitmap scan fails loudly.
import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
} from "viem";

import { HASH_SUITE_KECCAK_256 } from "../constants.js";
import { ShrincsPaymasterClient } from "../shrincsPaymasterClient.js";
import { ShrincsSigner } from "../shrincsSigner.js";
import { BITMAP_WORD_BATCH, LEAVES_PER_WORD } from "../internal/leafBitmap.js";

const PAYMASTER = "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4" as Address;
const ACCOUNT = "0x00000000000000000000000000000000000000a1" as Address;
const COMMITMENT = ("0x" + "11".repeat(32)) as Hex;
const CHAIN_ID = 31337;

/// Large enough that a whole-bitmap scan is clearly wrong (257 words) while
/// staying cheap to decode: the point is the asymptotics, not the absolute size.
const LARGE_BUDGET = 1 << 16;

/// Bitmap word for an epoch that has consumed leaves `1..usedThrough` in order.
/// Bit 0 of word 0 is leaf 0, which is never a valid signing leaf and is never
/// set on-chain.
function prefixWord(wordIndex: number, usedThrough: number): bigint {
  let word = 0n;
  const first = wordIndex === 0 ? 1 : wordIndex * LEAVES_PER_WORD;
  const last = wordIndex * LEAVES_PER_WORD + LEAVES_PER_WORD - 1;
  for (let leaf = first; leaf <= Math.min(last, usedThrough); leaf++) {
    word |= 1n << BigInt(leaf % LEAVES_PER_WORD);
  }
  return word;
}

interface ScanCost {
  roundTrips: number;
  wordsRead: number;
}

function countingPublicClient(params: {
  maxSignatures: number;
  usedThrough: number;
  cost: ScanCost;
}): PublicClient {
  return {
    getChainId: async () => CHAIN_ID,
    getCode: async () => "0x60006000" as Hex,
    readContract: async ({ functionName }: { functionName: string }) => {
      if (functionName === "getShrincsVerifier") {
        return [
          COMMITMENT,
          HASH_SUITE_KECCAK_256,
          0n,
          params.maxSignatures,
          params.usedThrough,
        ];
      }
      throw new Error(`unexpected paymaster read: ${functionName}`);
    },
    multicall: async ({
      contracts,
    }: {
      contracts: readonly { functionName: string; args: readonly bigint[] }[];
    }) => {
      params.cost.roundTrips += 1;
      params.cost.wordsRead += contracts.length;
      return contracts.map((call) => {
        if (call.functionName !== "statefulLeafBitmapWord") {
          throw new Error(`unexpected batched read: ${call.functionName}`);
        }
        return {
          status: "success" as const,
          result: prefixWord(Number(call.args[0]), params.usedThrough),
        };
      });
    },
  } as unknown as PublicClient;
}

async function makeClient(publicClient: PublicClient) {
  const signer = await ShrincsSigner.create(
    new TextEncoder().encode("scan cost master (hd seed padding)")
  );
  return new ShrincsPaymasterClient({
    paymasterAddress: PAYMASTER,
    publicClient,
    walletClient: {} as WalletClient,
    signer,
    commitment: COMMITMENT,
    derivationIndex: 0,
    chainId: CHAIN_ID,
    account: ACCOUNT,
  });
}

/// Runs the scan `scans` times against one client, reporting the cost of the
/// LAST scan only. `scans: 1` is a cold client; more exercises the warm
/// frontier, which is what a paymaster signing many sponsorships in one epoch
/// actually does.
async function measure(params: {
  maxSignatures: number;
  usedThrough: number;
  scans?: number;
}): Promise<{ leaf: number; cost: ScanCost; elapsedMs: number }> {
  const cost: ScanCost = { roundTrips: 0, wordsRead: 0 };
  const client = await makeClient(countingPublicClient({ ...params, cost }));
  const verifier = {
    commitment: COMMITMENT,
    hashSuite: HASH_SUITE_KECCAK_256,
    keyVersion: 0n,
    maxSignatures: params.maxSignatures,
    statefulLeavesUsed: params.usedThrough,
  };
  let leaf = 0;
  const scans = params.scans ?? 1;
  for (let scan = 0; scan < scans; scan++) {
    if (scan === scans - 1) {
      cost.roundTrips = 0;
      cost.wordsRead = 0;
    }
    const started = Date.now();
    leaf = await client.lowestUnusedLeaf(verifier);
    if (scan === scans - 1) {
      return { leaf, cost, elapsedMs: Date.now() - started };
    }
  }
  throw new Error("measure requires at least one scan");
}

describe("lowest-unused-leaf scan cost", () => {
  it("reads a bounded number of words on a fresh 2^16-leaf budget", async () => {
    const { leaf, cost, elapsedMs } = await measure({
      maxSignatures: LARGE_BUDGET,
      usedThrough: 0,
    });
    console.log(
      `fresh 2^16 budget: leaf=${leaf} roundTrips=${cost.roundTrips} wordsRead=${cost.wordsRead} elapsed=${elapsedMs}ms`
    );
    expect(leaf).toBe(1);
    expect(cost.roundTrips).toBe(1);
    expect(cost.wordsRead).toBeLessThanOrEqual(32);
  });

  it("reads a bounded number of words on a nearly-exhausted 2^16-leaf budget", async () => {
    const usedThrough = 60_000;
    const { leaf, cost, elapsedMs } = await measure({
      maxSignatures: LARGE_BUDGET,
      usedThrough,
    });
    console.log(
      `60k used of 2^16: leaf=${leaf} roundTrips=${cost.roundTrips} wordsRead=${cost.wordsRead} elapsed=${elapsedMs}ms`
    );
    expect(leaf).toBe(usedThrough + 1);
    // A cold client must still cross the exhausted prefix, but geometric batch
    // growth keeps that logarithmic in the prefix length, not one trip per 32.
    expect(cost.roundTrips).toBeLessThanOrEqual(5);
  });

  it("costs one small round trip once the frontier is warm", async () => {
    const usedThrough = 60_000;
    const { leaf, cost, elapsedMs } = await measure({
      maxSignatures: LARGE_BUDGET,
      usedThrough,
      scans: 2,
    });
    console.log(
      `60k used of 2^16 (warm): leaf=${leaf} roundTrips=${cost.roundTrips} wordsRead=${cost.wordsRead} elapsed=${elapsedMs}ms`
    );
    expect(leaf).toBe(usedThrough + 1);
    expect(cost.roundTrips).toBe(1);
    expect(cost.wordsRead).toBeLessThanOrEqual(BITMAP_WORD_BATCH);
  });

  it("still reads the whole prefix cheaply for the deployed 4096-leaf budget", async () => {
    const { leaf, cost, elapsedMs } = await measure({
      maxSignatures: 4096,
      usedThrough: 4000,
    });
    console.log(
      `4000 used of 4096: leaf=${leaf} roundTrips=${cost.roundTrips} wordsRead=${cost.wordsRead} elapsed=${elapsedMs}ms`
    );
    expect(leaf).toBe(4001);
    expect(cost.roundTrips).toBe(1);
  });
});
