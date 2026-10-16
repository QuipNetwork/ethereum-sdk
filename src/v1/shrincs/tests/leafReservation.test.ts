// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { StatefulBudgetExhaustedError } from "../errors.js";
import {
  LeafReservationStore,
  reserveLowestLeaf,
  type LeafReservationKey,
} from "../leafReservation.js";

const KEY: LeafReservationKey = {
  commitment: "0xABCD",
  keyVersion: 1n,
};

const neverUsed = () => false;

describe("leafReservation", () => {
  it("hands out distinct leaves for sequential reservations under one key", async () => {
    const store = new LeafReservationStore();
    const first = await reserveLowestLeaf(store, KEY, neverUsed, 8);
    const second = await reserveLowestLeaf(store, KEY, neverUsed, 8);
    expect(first).toBe(1);
    expect(second).toBe(2);
  });

  it("skips a leaf the on-chain predicate reports as used", async () => {
    const store = new LeafReservationStore();
    const leaf = await reserveLowestLeaf(store, KEY, (l) => l === 1, 8);
    expect(leaf).toBe(2);
  });

  it("throws StatefulBudgetExhaustedError when no free leaf remains", async () => {
    const store = new LeafReservationStore();
    await reserveLowestLeaf(store, KEY, neverUsed, 1);
    await expect(
      reserveLowestLeaf(store, KEY, neverUsed, 1)
    ).rejects.toBeInstanceOf(StatefulBudgetExhaustedError);
  });

  it("throws when every leaf is on-chain used", async () => {
    const store = new LeafReservationStore();
    await expect(
      reserveLowestLeaf(store, KEY, () => true, 4)
    ).rejects.toBeInstanceOf(StatefulBudgetExhaustedError);
  });

  it("gives concurrent reservations distinct leaves (serialized per key)", async () => {
    const store = new LeafReservationStore();
    // An async predicate forces a microtask yield inside the critical section;
    // without per-key serialization both awaits would observe leaf 1 free.
    const isUsed = async (_leaf: number) => {
      await Promise.resolve();
      return false;
    };
    const [a, b] = await Promise.all([
      reserveLowestLeaf(store, KEY, isUsed, 8),
      reserveLowestLeaf(store, KEY, isUsed, 8),
    ]);
    expect(new Set([a, b]).size).toBe(2);
  });

  it("keeps reservations isolated across keys", async () => {
    const store = new LeafReservationStore();
    const a = await reserveLowestLeaf(store, KEY, neverUsed, 8);
    const b = await reserveLowestLeaf(
      store,
      { commitment: "0xABCD", keyVersion: 2n },
      neverUsed,
      8
    );
    const c = await reserveLowestLeaf(
      store,
      { commitment: "0xBEEF", keyVersion: 1n },
      neverUsed,
      8
    );
    expect(a).toBe(1);
    expect(b).toBe(1);
    expect(c).toBe(1);
  });

  it("treats the commitment case-insensitively", async () => {
    const store = new LeafReservationStore();
    const a = await reserveLowestLeaf(store, KEY, neverUsed, 8);
    const b = await reserveLowestLeaf(
      store,
      { commitment: "0xabcd", keyVersion: 1n },
      neverUsed,
      8
    );
    expect(a).toBe(1);
    expect(b).toBe(2);
  });
});
