// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getAddress } from "viem";

import { keccak256, toHex } from "viem";

import { computeCreate3Address } from "../../addresses.js";
import {
  CANONICAL_OPERATOR,
  LIVE_SALT_PREIMAGES,
  permissionlessAddress,
  senderGuardedAddress,
  senderGuardedRawSalt,
} from "../../internal/createxSalts.js";
import { NETWORK_ADDRESSES as V1_NETWORK_ADDRESSES } from "../../addresses.js";
import {
  CANONICAL_ENTRYPOINT_V07,
  NETWORK_ADDRESSES,
  V1_IDENTITY_DOMAIN,
  getShrincsAddresses,
  getShrincsWalletAddress,
  v1Commitment,
} from "../addresses.js";
import { UnsupportedNetworkError } from "../errors.js";

// The published registry — `DEPLOYMENTS.md`, `src/v1/shrincs/addresses.ts`, and
// `src/v1/addresses.json`. These are the addresses the SDK tells integrators to
// use, so they are pinned here as independent literals and then RE-DERIVED from
// (CreateX, CANONICAL_OPERATOR, salt preimage) below. Comparing the SDK's
// literals against literals would only detect edits to this file; re-deriving is
// what catches a changed salt string, a changed operator, or drift in the guard
// formula — the failures that put contracts at unpublished addresses.
const PUBLISHED = {
  WalletFactory: "0xA2B2F71456a799FCf4EF7A3111c4B96b3e928cc8",
  ShrincsWalletImplementation: "0x680840c831c6D147404a0e00edA08a5360564FBC",
  ShrincsPaymaster: "0x430c8c89492E3541e141148Dd7a7D6dD432e5890",
  ShrincsPaymasterImpl: "0x5E4E4003118a0F8825494D76E86Db2ed654992d2",
  ShrincsVerifier: "0xF2f9E6D692da41b089c3c261c41509669eEc5567",
} as const;

// Every derived row: published address ← the preimage it must derive from. The
// verifier is deliberately absent — it is hashsigs-solidity's own CREATE3 deploy
// on an unguarded salt, not ours to derive.
const DERIVED_ROWS = [
  ["WalletFactory", PUBLISHED.WalletFactory, LIVE_SALT_PREIMAGES.WalletFactoryProxy],
  [
    "ShrincsWalletImplementation",
    PUBLISHED.ShrincsWalletImplementation,
    LIVE_SALT_PREIMAGES.ShrincsWalletImplementation,
  ],
  ["ShrincsPaymaster", PUBLISHED.ShrincsPaymaster, LIVE_SALT_PREIMAGES.ShrincsPaymasterProxy],
  [
    "ShrincsPaymasterImpl",
    PUBLISHED.ShrincsPaymasterImpl,
    LIVE_SALT_PREIMAGES.ShrincsPaymasterImpl,
  ],
] as const;

describe("shrincs addresses", () => {
  it("exposes the canonical deterministic Shrincs addresses on the default entry", () => {
    const d = NETWORK_ADDRESSES.default;
    expect(d.EntryPoint).toBe(CANONICAL_ENTRYPOINT_V07);
    expect(d.ShrincsWalletImplementation).toBe(PUBLISHED.ShrincsWalletImplementation);
    expect(d.ShrincsPaymaster).toBe(PUBLISHED.ShrincsPaymaster);
    expect(d.ShrincsPaymasterImpl).toBe(PUBLISHED.ShrincsPaymasterImpl);
    expect(d.ShrincsVerifier).toBe(PUBLISHED.ShrincsVerifier);
  });

  it("addresses are valid checksummed addresses", () => {
    for (const a of Object.values(PUBLISHED)) {
      expect(getAddress(a)).toBe(a); // throws if the checksum is wrong
    }
  });

  it("getShrincsAddresses returns the default entry for every supported chain", () => {
    // The Shrincs contracts share one CREATE3-deterministic address set across
    // every supported chain, so each resolves to the same `default` entry.
    expect(getShrincsAddresses(1)).toEqual(NETWORK_ADDRESSES.default); // mainnet
    expect(getShrincsAddresses(8453)).toEqual(NETWORK_ADDRESSES.default); // Base
    expect(getShrincsAddresses(777)).toEqual(NETWORK_ADDRESSES.default); // MIDL testnet
    expect(getShrincsAddresses()).toEqual(NETWORK_ADDRESSES.default);
  });

  it("getShrincsAddresses throws UnsupportedNetworkError for unknown chain ids", () => {
    expect(() => getShrincsAddresses(999999)).toThrow(UnsupportedNetworkError);
  });

  it("getShrincsAddresses returns the default entry for the live testnets", () => {
    // Live V1.0.1 deployments as of 2026-08-27: Base Sepolia and OP Sepolia.
    expect(getShrincsAddresses(84532)).toEqual(NETWORK_ADDRESSES.default);
    expect(getShrincsAddresses(11155420)).toEqual(NETWORK_ADDRESSES.default);
  });

  it("getShrincsAddresses returns the default entry when chainId is omitted", () => {
    expect(getShrincsAddresses()).toEqual(NETWORK_ADDRESSES.default);
  });
});

describe("published registry re-derived from the canonical operator", () => {
  it.each(DERIVED_ROWS)(
    "%s derives from its salt preimage",
    (_name, published, preimage) => {
      expect(senderGuardedAddress(CANONICAL_OPERATOR, preimage)).toBe(published);
    },
  );

  it("the v1 registry's WalletFactory agrees with the derivation", () => {
    // Sourced from `src/v1/addresses.json` (written by `scripts/release.ts`).
    // The WalletFactory row is the live sender-guarded proxy; the remaining keys
    // in that file are sunset WOTS+-era rows with a different derivation.
    expect(getAddress(V1_NETWORK_ADDRESSES.default.WalletFactory)).toBe(
      senderGuardedAddress(CANONICAL_OPERATOR, LIVE_SALT_PREIMAGES.WalletFactoryProxy),
    );
  });

  it("keeps the squat surface closed: permissioned never equals permissionless", () => {
    for (const preimage of Object.values(LIVE_SALT_PREIMAGES)) {
      expect(senderGuardedAddress(CANONICAL_OPERATOR, preimage)).not.toBe(
        permissionlessAddress(CANONICAL_OPERATOR, preimage),
      );
    }
  });

  it("every canonical address is distinct", () => {
    const derived = Object.values(LIVE_SALT_PREIMAGES).map((p) =>
      senderGuardedAddress(CANONICAL_OPERATOR, p),
    );
    expect(new Set(derived).size).toBe(derived.length);
  });

  describe("raw salt layout", () => {
    it.each(Object.entries(LIVE_SALT_PREIMAGES))("%s", (_name, preimage) => {
      const body = senderGuardedRawSalt(CANONICAL_OPERATOR, preimage).slice(2);
      expect(body).toHaveLength(64);
      // bytes 0-19: the operator → CreateX takes the permissioned branch
      expect(body.slice(0, 40)).toBe(CANONICAL_OPERATOR.slice(2).toLowerCase());
      // byte 20: cross-chain flag OFF → the same address on every chain
      expect(body.slice(40, 42)).toBe("00");
    });
  });
});

describe("V1 identity codec (byte-exact with Solidity)", () => {
  // Fixed fixture shared with the Solidity golden test
  // (test/ShrincsWallet/behaviors/identity.t.sol).
  const statefulC = `0x${"11".repeat(32)}` as const;
  const statelessC = `0x${"22".repeat(32)}` as const;
  const owner = "0x00000000000000000000000000000000000000AA" as const;

  // The 32-byte commitment for the fixture, pinned. BOTH sides must return this
  // exact value — it proves the domain and ABI encoding agree.
  const GOLDEN =
    "0xd165e4bbba9307d943f384fcaeaeb3c123bd87cfb9124a19d0a14fd4a3ae57df";

  it("V1 identity domain matches Solidity", () => {
    expect(V1_IDENTITY_DOMAIN).toBe(
      keccak256(toHex("QUIP_SHRINCS_IDENTITY_V1"))
    );
  });

  it("v1Commitment matches the cross-language golden", () => {
    expect(v1Commitment(statefulC, statelessC, owner)).toBe(GOLDEN);
  });

  it("v1Commitment is a full 32-byte digest", () => {
    const id = v1Commitment(statefulC, statelessC, owner);
    expect((id.length - 2) / 2).toBe(32);
  });

  it("v1Commitment binds each input", () => {
    const base = v1Commitment(statefulC, statelessC, owner);
    expect(v1Commitment(`0x${"33".repeat(32)}`, statelessC, owner)).not.toBe(
      base
    );
    expect(v1Commitment(statefulC, `0x${"44".repeat(32)}`, owner)).not.toBe(
      base
    );
    expect(
      v1Commitment(
        statefulC,
        statelessC,
        "0x00000000000000000000000000000000000000bb"
      )
    ).not.toBe(base);
  });
});

describe("SHRINCS V1 address predictor", () => {
  const FACTORY = "0xE567d318819c067c26fC1E44D04beD2b4FE93BCC" as const;
  const statefulC = keccak256(toHex("stateful"));
  const statelessC = keccak256(toHex("stateless"));
  const owner = "0x00000000000000000000000000000000000000AA" as const;

  it("getShrincsWalletAddress equals computeCreate3Address(factory, v1Commitment)", () => {
    expect(getShrincsWalletAddress(FACTORY, statefulC, statelessC, owner)).toBe(
      computeCreate3Address(FACTORY, v1Commitment(statefulC, statelessC, owner))
    );
  });

  it("getShrincsWalletAddress is deterministic for the same identity", () => {
    const addr = getShrincsWalletAddress(FACTORY, statefulC, statelessC, owner);
    expect(getShrincsWalletAddress(FACTORY, statefulC, statelessC, owner)).toBe(
      addr
    );
  });

  it("getShrincsWalletAddress binds statefulC, statelessC, and owner", () => {
    const addr = getShrincsWalletAddress(FACTORY, statefulC, statelessC, owner);
    expect(
      getShrincsWalletAddress(
        FACTORY,
        keccak256(toHex("attacker-key")),
        statelessC,
        owner
      )
    ).not.toBe(addr);
    expect(
      getShrincsWalletAddress(
        FACTORY,
        statefulC,
        keccak256(toHex("other-stateless")),
        owner
      )
    ).not.toBe(addr);
    expect(
      getShrincsWalletAddress(
        FACTORY,
        statefulC,
        statelessC,
        "0x00000000000000000000000000000000000000bb"
      )
    ).not.toBe(addr);
  });
});
