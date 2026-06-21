// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getAddress } from "viem";

import {
  CANONICAL_ENTRYPOINT_V07,
  NETWORK_ADDRESSES,
  getShrincsAddresses,
} from "../addresses.js";

// Deterministic CREATE3 addresses from `script/PredictAddresses.s.sol` (salts
// QUIP:ShrincsWallet:V1.0 / QUIP:ShrincsPaymaster:Impl:V1.0 / :Proxy:V1.0).
// Pinned here so a salt/Deployer drift is caught.
const EXPECTED = {
  ShrincsWalletImplementation: "0xD1f3b80793D952551C26E31CC147e5df4149De76",
  ShrincsPaymaster: "0x50a75bAF3a1eB13A266cA9a6b0ac916A62BC392F",
  ShrincsPaymasterImpl: "0x5F5210F324Ab9dce1080DB0fab0c3C55b51209b6",
} as const;

describe("shrincs addresses", () => {
  it("exposes the canonical deterministic Shrincs addresses on the default entry", () => {
    const d = NETWORK_ADDRESSES.default;
    expect(d.EntryPoint).toBe(CANONICAL_ENTRYPOINT_V07);
    expect(d.ShrincsWalletImplementation).toBe(EXPECTED.ShrincsWalletImplementation);
    expect(d.ShrincsPaymaster).toBe(EXPECTED.ShrincsPaymaster);
    expect(d.ShrincsPaymasterImpl).toBe(EXPECTED.ShrincsPaymasterImpl);
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
