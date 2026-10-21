// Copyright (C) 2026 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Shared used-leaf bitmap scanning for the SHRINCS wallet and paymaster
/// clients. Both read the on-chain bitmap 256 leaves at a time via the
/// `statefulLeafBitmapWord(wordIndex)` view, decode the packed bits locally, and
/// treat any word that could not be read as fatal (never as "used") — that rule
/// keeps a transport failure from masquerading as an exhausted budget.
///
/// The scan is lazy: it walks words in growing batches from the caller's
/// starting point and stops at the first word offering a usable leaf, so a
/// signature costs a bounded number of reads no matter how large the key's
/// signature budget is.
import { LeafBitmapReadError } from "../errors.js";
import type { TryMulticallResult } from "../../internal/multicall.js";

/// Leaves packed into one bitmap word. Matches the contract, which stores
/// `usedStatefulLeafBitmap[keyVersion][leafIndex >> 8]` with bit `leafIndex &
/// 0xff`.
export const LEAVES_PER_WORD = 256;

/// Number of bitmap words needed to cover leaves `1..maxSignatures`. Leaf
/// `maxSignatures` lives in word `floor(maxSignatures / 256)`, so the count is
/// that index plus one. Returns 0 for a non-positive budget. Uses `Math.floor`
/// rather than `>> 8` because `maxSignatures` is a `uint32` that can exceed the
/// 2^31 range where JavaScript bitwise operators wrap.
export function bitmapWordCount(maxSignatures: number): number {
  if (maxSignatures <= 0) return 0;
  return Math.floor(maxSignatures / LEAVES_PER_WORD) + 1;
}

/// Narrow the `tryMulticall` results for a bitmap-word batch to the raw words,
/// throwing `LeafBitmapReadError` on the first entry that did not succeed. This
/// is the anti-replay-safety boundary: an unread word means the used state of
/// its 256 leaves is unknown, so the scan must fail loudly instead of guessing.
export function wordsFromResults(
  results: readonly TryMulticallResult<unknown>[],
  startWord = 0
): bigint[] {
  const words: bigint[] = [];
  for (let i = 0; i < results.length; i++) {
    const entry = results[i];
    if (!entry || entry.status !== "success") {
      throw new LeafBitmapReadError(startWord + i, {
        cause: entry?.status === "failure" ? entry.error : undefined,
      });
    }
    words[i] = entry.result as bigint;
  }
  return words;
}

/// Words fetched in the first round trip of a scan. Sized so the common answer
/// — a leaf near the frontier — costs one small multicall, rather than fetching
/// a large budget's whole bitmap up front.
export const BITMAP_WORD_BATCH = 32;

/// Ceiling on words per round trip. Batches double from `BITMAP_WORD_BATCH` so
/// a cold scan crossing a long exhausted prefix costs a logarithmic number of
/// round trips instead of one per 32 words, but never a multicall so large that
/// providers reject it.
export const MAX_BITMAP_WORD_BATCH = 256;

/// Reads `count` consecutive bitmap words starting at `startWord`. Injected by
/// the clients so the scan itself stays free of transport concerns; must throw
/// (never pad or guess) when a word cannot be read.
export type BitmapWordReader = (
  startWord: number,
  count: number
) => Promise<bigint[]>;

/// The bits of `wordIndex` that correspond to signing leaves in
/// `1..maxSignatures`. Leaf 0 is excluded (never a valid signing leaf, never set
/// on-chain) and so are the bits past the budget, so a word matching this mask
/// is genuinely exhausted rather than merely all-ones.
function signingLeafMask(wordIndex: number, maxSignatures: number): bigint {
  let mask = 0n;
  for (const leaf of leafRange(wordIndex, maxSignatures)) {
    mask |= 1n << BigInt(leaf % LEAVES_PER_WORD);
  }
  return mask;
}

function* leafRange(wordIndex: number, maxSignatures: number): Generator<number> {
  const first = Math.max(wordIndex * LEAVES_PER_WORD, 1);
  const last = Math.min(wordIndex * LEAVES_PER_WORD + LEAVES_PER_WORD - 1, maxSignatures);
  for (let leaf = first; leaf <= last; leaf++) yield leaf;
}

/// Every signing leaf this word covers is used on-chain. Such a word can never
/// yield a leaf again in this epoch, so the scan may skip it permanently.
export function isWordExhausted(
  word: bigint,
  wordIndex: number,
  maxSignatures: number
): boolean {
  const mask = signingLeafMask(wordIndex, maxSignatures);
  return (word & mask) === mask;
}

/// Lowest leaf this word covers that is free on-chain and not rejected by
/// `skip`, or `undefined` when the word offers none.
export function lowestUnusedLeafInWord(
  word: bigint,
  wordIndex: number,
  maxSignatures: number,
  skip?: (leaf: number) => boolean
): number | undefined {
  for (const leaf of leafRange(wordIndex, maxSignatures)) {
    if ((word & (1n << BigInt(leaf % LEAVES_PER_WORD))) !== 0n) continue;
    if (skip?.(leaf)) continue;
    return leaf;
  }
  return undefined;
}

export interface LeafScanResult {
  /// The lowest acceptable leaf, or `undefined` when the budget offers none.
  leaf: number | undefined;
  /// Index of the first word that still holds a free leaf on-chain. Every word
  /// below it is exhausted, and exhaustion is permanent within an epoch, so a
  /// later scan of the same epoch may start here (see `LeafScanFrontier`).
  frontierWord: number;
}

/// Finds the lowest unused signing leaf by walking the bitmap a batch of words
/// at a time and stopping at the first word that offers one, instead of
/// fetching and decoding the whole bitmap. Cost is bounded by the distance from
/// `startWord` to the answer, not by `maxSignatures`.
///
/// `skip` rejects leaves the bitmap reports as free but that must not sign
/// (in-process reservations, revocation targets). Skipped leaves never advance
/// the frontier: only on-chain exhaustion is permanent, so a word held back
/// solely by `skip` must stay in range of the next scan.
export async function findLowestUnusedLeaf(params: {
  maxSignatures: number;
  readWords: BitmapWordReader;
  startWord?: number;
  skip?: (leaf: number) => boolean;
  batchSize?: number;
}): Promise<LeafScanResult> {
  const wordCount = bitmapWordCount(params.maxSignatures);
  let batchSize = params.batchSize ?? BITMAP_WORD_BATCH;
  let frontierWord = Math.min(Math.max(params.startWord ?? 0, 0), wordCount);
  let start = frontierWord;
  while (start < wordCount) {
    const count = Math.min(batchSize, wordCount - start);
    const words = await params.readWords(start, count);
    for (let offset = 0; offset < count; offset++) {
      const wordIndex = start + offset;
      const word = words[offset];
      // Fail closed: a word the reader did not return leaves the used state of
      // its 256 leaves unknown, and signing at a leaf that is not confirmed
      // free risks one-time-signature reuse.
      if (word === undefined) throw new LeafBitmapReadError(wordIndex);
      if (isWordExhausted(word, wordIndex, params.maxSignatures)) {
        if (frontierWord === wordIndex) frontierWord = wordIndex + 1;
        continue;
      }
      const leaf = lowestUnusedLeafInWord(
        word,
        wordIndex,
        params.maxSignatures,
        params.skip
      );
      if (leaf !== undefined) return { leaf, frontierWord };
    }
    start += count;
    batchSize = Math.min(batchSize * 2, MAX_BITMAP_WORD_BATCH);
  }
  return { leaf: undefined, frontierWord };
}
