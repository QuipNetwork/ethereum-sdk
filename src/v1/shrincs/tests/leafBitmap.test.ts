// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  bitmapWordCount,
  wordsFromResults,
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
