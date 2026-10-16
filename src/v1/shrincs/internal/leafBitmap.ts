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
/// clients. Both read the on-chain bitmap one 256-bit word at a time via the
/// `statefulLeafBitmapWord(wordIndex)` view, decode the packed bits locally, and
/// treat any word that could not be read as fatal (never as "used"). Reading a
/// whole word per call replaces the previous one-call-per-leaf scan, and the
/// fatal-on-failure rule keeps a transport failure from masquerading as an
/// exhausted budget.
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

/// Decode the set of used leaves in `1..maxSignatures` from bitmap `words`,
/// where `words[i]` is the raw word for `wordIndex === i`. Leaf 0 is never a
/// valid signing leaf and is skipped.
export function usedLeavesFromWords(
  words: readonly bigint[],
  maxSignatures: number
): Set<number> {
  const used = new Set<number>();
  for (let leaf = 1; leaf <= maxSignatures; leaf++) {
    const wordIndex = Math.floor(leaf / LEAVES_PER_WORD);
    const word = words[wordIndex];
    if (word === undefined) {
      // Fail closed: a word missing from `words` leaves the used state of its
      // 256 leaves unknown. Never treat it as free — that would risk signing at
      // an already-consumed one-time leaf. Callers pass exactly
      // `bitmapWordCount` words, so this only fires if that contract is broken.
      throw new LeafBitmapReadError(wordIndex);
    }
    if ((word & (BigInt(1) << BigInt(leaf % LEAVES_PER_WORD))) !== BigInt(0)) {
      used.add(leaf);
    }
  }
  return used;
}

/// Narrow the `tryMulticall` results for a bitmap-word batch to the raw words,
/// throwing `LeafBitmapReadError` on the first entry that did not succeed. This
/// is the anti-replay-safety boundary: an unread word means the used state of
/// its 256 leaves is unknown, so the scan must fail loudly instead of guessing.
export function wordsFromResults(
  results: readonly TryMulticallResult<unknown>[]
): bigint[] {
  const words: bigint[] = [];
  for (let i = 0; i < results.length; i++) {
    const entry = results[i];
    if (!entry || entry.status !== "success") {
      throw new LeafBitmapReadError(i, {
        cause: entry?.status === "failure" ? entry.error : undefined,
      });
    }
    words[i] = entry.result as bigint;
  }
  return words;
}
