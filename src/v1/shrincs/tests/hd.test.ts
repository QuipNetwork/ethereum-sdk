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
  deriveQuipSeed,
  masterNodeFromSeed,
  quipHdPath,
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

describe("deriveQuipSeed", () => {
  it("returns a 32-byte hex seed, deterministically", () => {
    const a = deriveQuipSeed(SEED, 0);
    expect(a).toMatch(/^0x[0-9a-f]{64}$/);
    expect(deriveQuipSeed(SEED, 0)).toBe(a);
  });

  it("separates every path level", () => {
    const base = deriveQuipSeed(SEED, 0);
    expect(deriveQuipSeed(SEED, 1)).not.toBe(base);
    expect(deriveQuipSeed(SEED, 0, { account: 1 })).not.toBe(base);
    expect(deriveQuipSeed(SEED, 0, { network: NETWORK_QUIP + 1 })).not.toBe(base);
    expect(deriveQuipSeed(SEED, 0, { algorithm: 1 })).not.toBe(base);
  });

  it("defaults match explicit experimental/QUIP/account-0 options", () => {
    expect(
      deriveQuipSeed(SEED, 3, {
        algorithm: ALGORITHM_EXPERIMENTAL,
        network: NETWORK_QUIP,
        account: 0,
      })
    ).toBe(deriveQuipSeed(SEED, 3));
  });
});

describe("quipHdPath", () => {
  it("renders the default path", () => {
    expect(quipHdPath(0)).toBe("m/20814'/2147483647'/20049'/0'/0'");
  });

  it("renders overridden levels", () => {
    expect(quipHdPath(5, { account: 2, algorithm: 7, network: 9 })).toBe(
      "m/20814'/7'/9'/2'/5'"
    );
  });
});

describe("QUIP HD v1 regression vectors", () => {
  const VECTOR_SEED = new TextEncoder().encode(
    "QUIP HD v1 regression vector seed"
  );

  it("never drifts", () => {
    expect(deriveQuipSeed(VECTOR_SEED, 0)).toBe("0xe384e03583d60da36e3fdbad396a0f3a9c98512007bd07999d9f8db870db8bb2");
    expect(deriveQuipSeed(VECTOR_SEED, 1)).toBe("0xafe51b913c23f2baf73026cdc8c6cdf2477a01116e525f30ba0f224a76198700");
    expect(deriveQuipSeed(VECTOR_SEED, 2147483646)).toBe("0xd20cef6c7abf8265603938a64a5028948867107a63f4d9f086aa9cf6f8e475c9");
  });
});
