// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Hex } from "viem";

import { StatefulBudgetExhaustedError } from "./errors.js";

/// Identifies the one-time-signature keyspace a reservation belongs to. The
/// on-chain used bitmap is namespaced by the key epoch, so two reservations are
/// only in conflict when they share both the public-key commitment and the
/// epoch (`keyVersion`). The commitment is compared case-insensitively.
export interface LeafReservationKey {
  commitment: Hex;
  keyVersion: bigint;
}

function keyId(key: LeafReservationKey): string {
  return `${key.commitment.toLowerCase()}:${key.keyVersion.toString()}`;
}

/// In-process record of stateful leaves already handed out (reserved) for
/// signing but not yet observable as used on-chain. It closes the window where a
/// sign-then-retry or two concurrent sign paths would otherwise read the bitmap,
/// both see the same lowest-unused leaf, and produce two signatures at one leaf
/// — an OTS reuse that is forgeable.
///
/// The store is per-client-instance: two clients for different wallets must not
/// share it, but every op from one client instance must. There is deliberately
/// no release API — a reservation persists for the instance lifetime, and the
/// on-chain bitmap is the durable backstop once a signed op lands.
export class LeafReservationStore {
  private readonly reserved = new Map<string, Set<number>>();
  private readonly tails = new Map<string, Promise<unknown>>();

  private reservedSet(id: string): Set<number> {
    let set = this.reserved.get(id);
    if (!set) {
      set = new Set<number>();
      this.reserved.set(id, set);
    }
    return set;
  }

  /// Runs `fn` with exclusive access to a key's reservation set, serializing
  /// concurrent callers so an async selection step cannot let two of them pick
  /// the same leaf. Failures do not poison the chain: the next waiter still runs.
  async withKeyLock<T>(
    key: LeafReservationKey,
    fn: (reserved: Set<number>) => Promise<T> | T
  ): Promise<T> {
    const id = keyId(key);
    const prior = this.tails.get(id) ?? Promise.resolve();
    const run = prior.then(() => fn(this.reservedSet(id)));
    // Keep the chain alive regardless of this caller's outcome.
    this.tails.set(
      id,
      run.then(
        () => undefined,
        () => undefined
      )
    );
    return run;
  }
}

/// Reserves the lowest leaf in `minLeaf..maxSignatures` that is neither reported
/// by `isUsedOrReserved` (the on-chain used check) nor already reserved in
/// `store`, atomically adding it to the store before returning. Selection is
/// serialized per key so concurrent callers receive distinct leaves even when
/// the check is async. `minLeaf` (default 1) lets a caller exclude a reserved
/// low range: the SHRINCS wallet reserves leaves `[1..MAX_DEPLOY_CHAINS]` for
/// deploy authorizations (`e3r`), so it signs only from `MAX_DEPLOY_CHAINS + 1`.
/// Throws `StatefulBudgetExhaustedError` when no free leaf remains.
export function reserveLowestLeaf(
  store: LeafReservationStore,
  key: LeafReservationKey,
  isUsedOrReserved: (leaf: number) => boolean | Promise<boolean>,
  maxSignatures: number,
  minLeaf = 1
): Promise<number> {
  return store.withKeyLock(key, async (reserved) => {
    for (let leaf = minLeaf; leaf <= maxSignatures; leaf++) {
      if (reserved.has(leaf)) continue;
      if (await isUsedOrReserved(leaf)) continue;
      reserved.add(leaf);
      return leaf;
    }
    throw new StatefulBudgetExhaustedError(maxSignatures, maxSignatures);
  });
}

/// Records `leaf` as reserved for `key` without scanning — used when a caller
/// supplies an explicit leaf override so a later automatic pick cannot collide
/// with it. Idempotent; serialized per key like `reserveLowestLeaf`.
export function reserveExplicitLeaf(
  store: LeafReservationStore,
  key: LeafReservationKey,
  leaf: number
): Promise<void> {
  return store.withKeyLock(key, (reserved) => {
    reserved.add(leaf);
  });
}
