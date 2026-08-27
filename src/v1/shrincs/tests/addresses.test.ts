// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getAddress, keccak256, toHex } from "viem";

import { computeVaultAddress } from "../../addresses.js";
import {
  CANONICAL_ENTRYPOINT_V07,
  NETWORK_ADDRESSES,
  V1_IDENTITY_DOMAIN,
  getShrincsAddresses,
  getShrincsWalletAddress,
  v1Commitment,
} from "../addresses.js";

// Deterministic sender-guarded CreateX CREATE3 addresses from
// `script/PredictAddresses.s.sol`, derived for the canonical DEPLOY_OPERATOR
// `0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26`. The impl salts bind the
// verifier scheme tag: `"QUIP:ShrincsWallet:V1.1:" ‖
// keccak256("shrincs-256s-keccak")` (and the paymaster-impl analog); the proxy
// salt is the plain `QUIP:ShrincsPaymaster:Proxy:V1.1`. Pinned here so a
// salt/operator drift is caught. `ShrincsVerifier` is the canonical
// hashsigs-solidity CREATE3 deploy the implementations pin.
const EXPECTED = {
  ShrincsWalletImplementation: "0xb84a596A6fB567FC4634b4f49212410D1193140e",
  ShrincsPaymaster: "0xE38420930EBD214FE8FEb403dd66F4887AEF76E8",
  ShrincsPaymasterImpl: "0xfc5b4E75CA03c260255523DbbF56e93F9cbB5c59",
  ShrincsVerifier: "0x9154dA0BA19600C543a8c5ed1B1c44af415B5688",
} as const;

describe("shrincs addresses", () => {
  it("exposes the canonical deterministic Shrincs addresses on the default entry", () => {
    const d = NETWORK_ADDRESSES.default;
    expect(d.EntryPoint).toBe(CANONICAL_ENTRYPOINT_V07);
    expect(d.ShrincsWalletImplementation).toBe(EXPECTED.ShrincsWalletImplementation);
    expect(d.ShrincsPaymaster).toBe(EXPECTED.ShrincsPaymaster);
    expect(d.ShrincsPaymasterImpl).toBe(EXPECTED.ShrincsPaymasterImpl);
    expect(d.ShrincsVerifier).toBe(EXPECTED.ShrincsVerifier);
  });

  it("addresses are valid checksummed addresses", () => {
    for (const a of Object.values(EXPECTED)) {
      expect(getAddress(a)).toBe(a); // throws if the checksum is wrong
    }
  });

  it("getShrincsAddresses falls back to the default entry for any chain", () => {
    expect(getShrincsAddresses(1)).toEqual(NETWORK_ADDRESSES.default);
    expect(getShrincsAddresses(8453)).toEqual(NETWORK_ADDRESSES.default);
    expect(getShrincsAddresses()).toEqual(NETWORK_ADDRESSES.default);
  });
});

describe("V1 identity codec (byte-exact with Solidity)", () => {
  // Fixed fixture shared with the Solidity golden test
  // (`test/ShrincsWallet/behaviors/identity.t.sol`).
  const statefulC = `0x${"11".repeat(32)}` as const;
  const statelessC = `0x${"22".repeat(32)}` as const;
  const owner = "0x00000000000000000000000000000000000000AA" as const;
  const GOLDEN =
    "0xd165e4bbba9307d943f384fcaeaeb3c123bd87cfb9124a19d0a14fd4a3ae57df";

  it("V1 identity domain matches Solidity", () => {
    expect(V1_IDENTITY_DOMAIN).toBe(keccak256(toHex("QUIP_SHRINCS_IDENTITY_V1")));
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
    expect(v1Commitment(`0x${"33".repeat(32)}`, statelessC, owner)).not.toBe(base);
    expect(v1Commitment(statefulC, `0x${"44".repeat(32)}`, owner)).not.toBe(base);
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

  it("getShrincsWalletAddress equals computeVaultAddress(factory, v1Commitment)", () => {
    expect(getShrincsWalletAddress(FACTORY, statefulC, statelessC, owner)).toBe(
      computeVaultAddress(FACTORY, v1Commitment(statefulC, statelessC, owner))
    );
  });

  it("getShrincsWalletAddress is deterministic for the same identity", () => {
    expect(getShrincsWalletAddress(FACTORY, statefulC, statelessC, owner)).toBe(
      getShrincsWalletAddress(FACTORY, statefulC, statelessC, owner)
    );
  });
});
