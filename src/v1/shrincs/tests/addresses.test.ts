// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getAddress } from "viem";

import { keccak256, toHex } from "viem";

import {
  CANONICAL_ENTRYPOINT_V07,
  DEPLOY_CHAIN_ORDER,
  NETWORK_ADDRESSES,
  deployVaultSalt,
  getShrincsAddresses,
  getShrincsWalletAddress,
  quipDeployChainIndex,
} from "../addresses.js";
import { MAX_DEPLOY_CHAINS } from "../constants.js";
import { UnsupportedNetworkError } from "../errors.js";

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

  it("getShrincsAddresses returns the default entry for BASE_SEPOLIA", () => {
    expect(getShrincsAddresses(84532)).toEqual(NETWORK_ADDRESSES.default);
  });

  it("getShrincsAddresses returns the default entry when chainId is omitted", () => {
    expect(getShrincsAddresses()).toEqual(NETWORK_ADDRESSES.default);
  });
});

describe("quipDeployChainIndex", () => {
  it("returns the 1-based position in the committed deploy list", () => {
    // Never 0 — leaf 0 is invalid, so the first chain maps to deploy leaf 1.
    expect(quipDeployChainIndex(DEPLOY_CHAIN_ORDER[0]!)).toBe(1);
    expect(quipDeployChainIndex(DEPLOY_CHAIN_ORDER[6]!)).toBe(7); // MIDL, last
  });

  it("assigns a distinct index to every listed chain", () => {
    const indices = DEPLOY_CHAIN_ORDER.map((c) => quipDeployChainIndex(c));
    expect(new Set(indices).size).toBe(DEPLOY_CHAIN_ORDER.length);
  });

  it("throws UnsupportedNetworkError for a chain not on the deploy list", () => {
    expect(() => quipDeployChainIndex(999999)).toThrow(UnsupportedNetworkError);
  });

  it("keeps the committed list within the reserved deploy-leaf range", () => {
    expect(DEPLOY_CHAIN_ORDER.length).toBeLessThanOrEqual(MAX_DEPLOY_CHAINS);
  });

  it("holds no duplicate chain (each maps to one deploy leaf)", () => {
    expect(new Set(DEPLOY_CHAIN_ORDER).size).toBe(DEPLOY_CHAIN_ORDER.length);
  });
});

describe("SHRINCS deploy salt / address (e3r)", () => {
  const FACTORY = "0xE567d318819c067c26fC1E44D04beD2b4FE93BCC" as const;
  const vaultId = keccak256(toHex("vault-1"));
  const commitment = keccak256(toHex("main-commitment"));

  it("deployVaultSalt is deterministic for the same (vaultId, commitment)", () => {
    expect(deployVaultSalt(vaultId, commitment)).toBe(
      deployVaultSalt(vaultId, commitment)
    );
  });

  it("deployVaultSalt binds BOTH the vault and the commitment", () => {
    const base = deployVaultSalt(vaultId, commitment);
    expect(deployVaultSalt(keccak256(toHex("vault-2")), commitment)).not.toBe(base);
    expect(deployVaultSalt(vaultId, keccak256(toHex("other")))).not.toBe(base);
  });

  it("getShrincsWalletAddress is deterministic and commitment-bound", () => {
    const addr = getShrincsWalletAddress(FACTORY, vaultId, commitment);
    expect(getShrincsWalletAddress(FACTORY, vaultId, commitment)).toBe(addr);
    // A different key commitment => a different counterfactual address, which is
    // exactly what stops an attacker taking the victim's address (e3r).
    expect(
      getShrincsWalletAddress(FACTORY, vaultId, keccak256(toHex("attacker-key")))
    ).not.toBe(addr);
  });
});
