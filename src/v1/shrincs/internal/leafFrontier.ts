// Copyright (C) 2026 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/// Per-epoch memory of how far the used-leaf bitmap has been consumed, so a
/// scan for the lowest unused leaf can resume where the last one stopped
/// instead of re-reading the exhausted prefix on every signature.
///
/// Soundness rests on the bitmap being append-only within an epoch: a leaf is
/// marked used and never released, and the only reset (`rotateStatefulKey`)
/// bumps `keyVersion`, which is part of the cache key. So "every word below W
/// is exhausted" stays true once observed. The cache is an optimisation only —
/// a cold or stale-low frontier costs extra reads, never a wrong leaf.
import {
  leafReservationKeyId,
  type LeafReservationKey,
} from "../leafReservation.js";

export class LeafScanFrontier {
  private readonly frontiers = new Map<string, number>();

  /// The word index a scan for `key` may start from.
  startWord(key: LeafReservationKey): number {
    return this.frontiers.get(leafReservationKeyId(key)) ?? 0;
  }

  /// Records an observed frontier, keeping the highest seen. Out-of-order or
  /// stale observations (a concurrent scan that started earlier) cannot move
  /// the frontier backwards and so cannot make a later scan skip a free leaf.
  advance(key: LeafReservationKey, word: number): void {
    const id = leafReservationKeyId(key);
    const current = this.frontiers.get(id) ?? 0;
    if (word > current) this.frontiers.set(id, word);
  }
}
