// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { toHex } from "viem";

import {
  ALGORITHM_EXPERIMENTAL,
  HARDENED_OFFSET,
  NETWORK_QUIP,
  QUIP_HD_PURPOSE,
  deriveHardenedChild,
  masterNodeFromSeed,
} from "../hd.js";
import { ShrincsHdDerivationError } from "../errors.js";

const SEED = new TextEncoder().encode("a deterministic test seed 32b+..");

describe("hd constants", () => {
  it("pins the QUIP path registry values", () => {
    expect(QUIP_HD_PURPOSE).toBe(0x514e);
    expect(ALGORITHM_EXPERIMENTAL).toBe(0x7fffffff);
    expect(NETWORK_QUIP).toBe(20049);
    expect(HARDENED_OFFSET).toBe(0x80000000);
  });
});

describe("masterNodeFromSeed", () => {
  it("returns 32-byte key and chain code, deterministically", () => {
    const a = masterNodeFromSeed(SEED);
    const b = masterNodeFromSeed(SEED);
    expect(a.key).toHaveLength(32);
    expect(a.chainCode).toHaveLength(32);
    expect(toHex(a.key)).toBe(toHex(b.key));
    expect(toHex(a.chainCode)).toBe(toHex(b.chainCode));
    expect(toHex(a.key)).not.toBe(toHex(a.chainCode));
  });

  it("rejects seeds shorter than 16 bytes", () => {
    expect(() => masterNodeFromSeed(new Uint8Array(15))).toThrow(
      ShrincsHdDerivationError
    );
  });
});

describe("deriveHardenedChild", () => {
  const node = masterNodeFromSeed(SEED);

  it("derives distinct children for distinct indices", () => {
    const c0 = deriveHardenedChild(node, 0);
    const c1 = deriveHardenedChild(node, 1);
    expect(toHex(c0.key)).not.toBe(toHex(c1.key));
  });

  it("is deterministic per index", () => {
    expect(toHex(deriveHardenedChild(node, 7).key)).toBe(
      toHex(deriveHardenedChild(node, 7).key)
    );
  });

  it("accepts the top of the hardened range", () => {
    expect(deriveHardenedChild(node, HARDENED_OFFSET - 1).key).toHaveLength(32);
  });

  it("rejects out-of-range and non-integer indices", () => {
    for (const bad of [-1, HARDENED_OFFSET, 1.5, Number.NaN]) {
      expect(() => deriveHardenedChild(node, bad)).toThrow(
        ShrincsHdDerivationError
      );
    }
  });
});
