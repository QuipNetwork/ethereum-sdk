// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  BITMAP_WORD_BATCH,
  LEAVES_PER_WORD,
  findLowestUnusedLeaf,
  isWordExhausted,
  lowestUnusedLeafInWord,
} from "../internal/leafBitmap.js";
import { LeafScanFrontier } from "../internal/leafFrontier.js";
import { LeafBitmapReadError } from "../errors.js";

const FULL_WORD = (1n << 256n) - 1n;

/// Bitmap word for an epoch that consumed leaves `1..usedThrough` in order.
function prefixWord(wordIndex: number, usedThrough: number): bigint {
  let word = 0n;
  const first = Math.max(wordIndex * LEAVES_PER_WORD, 1);
  const last = Math.min(
    wordIndex * LEAVES_PER_WORD + LEAVES_PER_WORD - 1,
    usedThrough
  );
  for (let leaf = first; leaf <= last; leaf++) {
    word |= 1n << BigInt(leaf % LEAVES_PER_WORD);
  }
  return word;
}

function prefixReader(usedThrough: number, cost?: { wordsRead: number; roundTrips: number }) {
  return async (startWord: number, count: number) => {
    if (cost) {
      cost.roundTrips += 1;
      cost.wordsRead += count;
    }
    return Array.from({ length: count }, (_, i) => prefixWord(startWord + i, usedThrough));
  };
}

describe("isWordExhausted", () => {
  it("treats word 0 as exhausted without leaf 0's bit, which is never set on-chain", () => {
    // Leaves 1..255 used; bit 0 (leaf 0) is not a signing leaf and stays clear.
    // Requiring it would freeze the scan frontier at word 0 forever.
    expect(isWordExhausted(prefixWord(0, 255), 0, 1000)).toBe(true);
  });

  it("treats a word as exhausted once every in-budget leaf is used", () => {
    // Budget stops at leaf 300, so word 1 only owns leaves 256..300.
    expect(isWordExhausted(prefixWord(1, 300), 1, 300)).toBe(true);
  });

  it("does not treat a word with a free leaf as exhausted", () => {
    expect(isWordExhausted(prefixWord(0, 254), 0, 1000)).toBe(false);
  });
});

describe("lowestUnusedLeafInWord", () => {
  it("skips leaf 0 and returns the lowest free signing leaf", () => {
    expect(lowestUnusedLeafInWord(prefixWord(0, 5), 0, 1000)).toBe(6);
  });

  it("honours the skip predicate without consuming the skipped leaf", () => {
    const skipped = new Set([6, 7]);
    expect(
      lowestUnusedLeafInWord(prefixWord(0, 5), 0, 1000, (leaf) => skipped.has(leaf))
    ).toBe(8);
  });

  it("returns undefined when every in-budget leaf is used", () => {
    expect(lowestUnusedLeafInWord(FULL_WORD, 0, 100)).toBeUndefined();
  });

  it("ignores bits past the budget", () => {
    expect(lowestUnusedLeafInWord(prefixWord(0, 4), 0, 4)).toBeUndefined();
  });
});

describe("findLowestUnusedLeaf", () => {
  it("returns the first leaf of a fresh budget after a single batch", async () => {
    const cost = { wordsRead: 0, roundTrips: 0 };
    const { leaf } = await findLowestUnusedLeaf({
      maxSignatures: 1 << 20,
      readWords: prefixReader(0, cost),
    });
    expect(leaf).toBe(1);
    expect(cost.roundTrips).toBe(1);
    expect(cost.wordsRead).toBe(BITMAP_WORD_BATCH);
  });

  it("finds a leaf across a word boundary", async () => {
    const { leaf } = await findLowestUnusedLeaf({
      maxSignatures: 1000,
      readWords: prefixReader(255),
    });
    expect(leaf).toBe(256);
  });

  it("reports the frontier as the first word still holding a free leaf", async () => {
    const { leaf, frontierWord } = await findLowestUnusedLeaf({
      maxSignatures: 1 << 20,
      readWords: prefixReader(600),
    });
    expect(leaf).toBe(601);
    expect(frontierWord).toBe(2);
  });

  it("resumes from startWord instead of re-reading the exhausted prefix", async () => {
    const cost = { wordsRead: 0, roundTrips: 0 };
    const usedThrough = 900_000;
    const { leaf } = await findLowestUnusedLeaf({
      maxSignatures: 1 << 20,
      readWords: prefixReader(usedThrough, cost),
      startWord: Math.floor(usedThrough / LEAVES_PER_WORD),
    });
    expect(leaf).toBe(usedThrough + 1);
    expect(cost.roundTrips).toBe(1);
  });

  it("does not advance the frontier past a word held back only by skip", async () => {
    // Word 0 has leaf 256-worth of holes only via skip: leaves 1..255 used,
    // and the one free in-budget leaf below word 1 is skipped. The frontier
    // must not move past word 0, because skip is not durable state — the next
    // scan (a different caller, no reservation) must still see that leaf.
    const { leaf, frontierWord } = await findLowestUnusedLeaf({
      maxSignatures: 1 << 20,
      readWords: prefixReader(254),
      skip: (candidate) => candidate === 255,
    });
    expect(leaf).toBe(256);
    expect(frontierWord).toBe(0);
  });

  it("returns no leaf when the budget is fully consumed", async () => {
    const { leaf } = await findLowestUnusedLeaf({
      maxSignatures: 512,
      readWords: prefixReader(512),
    });
    expect(leaf).toBeUndefined();
  });

  it("fails closed when the reader returns fewer words than requested", async () => {
    // A short read must never decode as "those leaves are free" — that would
    // risk signing at an already-consumed one-time leaf.
    await expect(
      findLowestUnusedLeaf({
        maxSignatures: 1 << 20,
        readWords: async () => [],
      })
    ).rejects.toThrow(LeafBitmapReadError);
  });
});

describe("LeafScanFrontier", () => {
  const KEY = { commitment: ("0x" + "11".repeat(32)) as `0x${string}`, keyVersion: 0n };

  it("starts cold at word 0", () => {
    expect(new LeafScanFrontier().startWord(KEY)).toBe(0);
  });

  it("remembers an advanced frontier", () => {
    const frontier = new LeafScanFrontier();
    frontier.advance(KEY, 7);
    expect(frontier.startWord(KEY)).toBe(7);
  });

  it("never moves backwards, so a stale scan cannot make a later one skip a leaf", () => {
    const frontier = new LeafScanFrontier();
    frontier.advance(KEY, 7);
    frontier.advance(KEY, 3);
    expect(frontier.startWord(KEY)).toBe(7);
  });

  it("isolates epochs, because rotation resets the bitmap", () => {
    const frontier = new LeafScanFrontier();
    frontier.advance(KEY, 7);
    expect(frontier.startWord({ ...KEY, keyVersion: 1n })).toBe(0);
  });

  it("isolates commitments", () => {
    const frontier = new LeafScanFrontier();
    frontier.advance(KEY, 7);
    expect(
      frontier.startWord({ ...KEY, commitment: ("0x" + "22".repeat(32)) as `0x${string}` })
    ).toBe(0);
  });
});
