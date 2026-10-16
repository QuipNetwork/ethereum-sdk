// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  bitmapWordCount,
  usedLeavesFromWords,
  wordsFromResults,
  LEAVES_PER_WORD,
} from "../internal/leafBitmap.js";
import { LeafBitmapReadError } from "../errors.js";
import type { TryMulticallResult } from "../../internal/multicall.js";

describe("bitmapWordCount", () => {
  it.each([
    [0, 0],
    [1, 1],
    [255, 1],
    [256, 2],
    [257, 2],
    [511, 2],
    [512, 3],
  ])("covers %i leaves with %i words", (maxSignatures, expected) => {
    expect(bitmapWordCount(maxSignatures)).toBe(expected);
  });

  it("returns 0 for a negative budget", () => {
    expect(bitmapWordCount(-5)).toBe(0);
  });
});

describe("usedLeavesFromWords", () => {
  it("decodes set bits into leaf indices, skipping leaf 0", () => {
    // Word 0, bits 1, 2, and 5 set -> leaves 1, 2, 5. Bit 0 (leaf 0) set but
    // never a valid signing leaf, so it must not appear.
    const word0 = (1n << 0n) | (1n << 1n) | (1n << 2n) | (1n << 5n);
    expect(usedLeavesFromWords([word0], 8)).toEqual(new Set([1, 2, 5]));
  });

  it("reads a leaf from the correct word and bit across a word boundary", () => {
    // Leaf 256 is bit 0 of word 1; leaf 257 is bit 1 of word 1.
    const words = [0n, (1n << 0n) | (1n << 1n)];
    expect(usedLeavesFromWords(words, 300)).toEqual(new Set([256, 257]));
  });

  it("ignores bits for leaves beyond maxSignatures", () => {
    const word0 = (1n << 3n) | (1n << 7n);
    // Only leaves up to 4 are in budget, so leaf 7's bit is not reported.
    expect(usedLeavesFromWords([word0], 4)).toEqual(new Set([3]));
  });

  it("fails closed when a required word is missing rather than treating it as free", () => {
    // Fewer words than the budget needs must never decode as "all leaves free".
    expect(() => usedLeavesFromWords([], LEAVES_PER_WORD)).toThrow(
      LeafBitmapReadError
    );
  });
});

describe("wordsFromResults", () => {
  it("returns the raw words when every read succeeds", () => {
    const results: TryMulticallResult<unknown>[] = [
      { status: "success", result: 7n },
      { status: "success", result: 0n },
    ];
    expect(wordsFromResults(results)).toEqual([7n, 0n]);
  });

  it("throws LeafBitmapReadError on the first failed word, carrying its index and cause", () => {
    const cause = new Error("rpc down");
    const results: TryMulticallResult<unknown>[] = [
      { status: "success", result: 3n },
      { status: "failure", error: cause },
    ];
    try {
      wordsFromResults(results);
      throw new Error("expected wordsFromResults to throw");
    } catch (err) {
      expect(err).toBeInstanceOf(LeafBitmapReadError);
      expect((err as LeafBitmapReadError).wordIndex).toBe(1);
      expect((err as LeafBitmapReadError).cause).toBe(cause);
    }
  });

  it("never confuses an unread word with a used leaf", () => {
    // A failed read must not decode as "all bits set" (every leaf used) — that
    // regression would make a transport failure look like an exhausted budget.
    const results: TryMulticallResult<unknown>[] = [{ status: "failure", error: new Error("x") }];
    expect(() => wordsFromResults(results)).toThrow(LeafBitmapReadError);
  });
});
