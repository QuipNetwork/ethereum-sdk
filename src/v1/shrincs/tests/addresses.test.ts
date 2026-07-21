// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getAddress } from "viem";

import {
  CANONICAL_ENTRYPOINT_V07,
  NETWORK_ADDRESSES,
  getShrincsAddresses,
} from "../addresses.js";

// Deterministic CREATE3 addresses from `script/PredictAddresses.s.sol`. The
// impl salts bind the verifier scheme tag: `"QUIP:ShrincsWallet:V1.1:" ‖
// keccak256("shrincs-256s-keccak")` (and the paymaster-impl analog); the proxy
// salt is the plain `QUIP:ShrincsPaymaster:Proxy:V1.1`. Pinned here so a
// salt/Deployer drift is caught. `ShrincsVerifier` is the canonical
// hashsigs-solidity CREATE3 deploy the implementations pin.
const EXPECTED = {
  ShrincsWalletImplementation: "0x2A4C7Cc9117a37dC9498A67637C9Fcf109C5b2aC",
  ShrincsPaymaster: "0x681B88b513D1ee3ee9bD4f3A4f6f2F6a8d4d6365",
  ShrincsPaymasterImpl: "0xC318894cb679EAc20e26Ad0762Cce5411A3B2386",
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
