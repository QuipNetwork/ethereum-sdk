// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getAddress } from "viem";

import { keccak256, toHex } from "viem";

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
  DEPLOY_CHAIN_ORDER,
  NETWORK_ADDRESSES,
  deployVaultSalt,
  getShrincsAddresses,
  getShrincsWalletAddress,
  quipDeployChainIndex,
} from "../addresses.js";
import { MAX_DEPLOY_CHAINS } from "../constants.js";
import { UnsupportedNetworkError } from "../errors.js";

// The published registry — `DEPLOYMENTS.md`, `src/v1/shrincs/addresses.ts`, and
// `src/v1/addresses.json`. These are the addresses the SDK tells integrators to
// use, so they are pinned here as independent literals and then RE-DERIVED from
// (CreateX, CANONICAL_OPERATOR, salt preimage) below. Comparing the SDK's
// literals against literals would only detect edits to this file; re-deriving is
// what catches a changed salt string, a changed operator, or drift in the guard
// formula — the failures that put contracts at unpublished addresses.
const PUBLISHED = {
  WalletFactory: "0xdCD90563B912f82D2f23d5c7988B3Fec2da63471",
  ShrincsWalletImplementation: "0x33d3949117c8Bba7A3637C96a564a817E00c5aE0",
  ShrincsPaymaster: "0x077C06913777777DfABf951a5A0F8CA665764ac9",
  ShrincsPaymasterImpl: "0x995bDB6768F25822Faafb2c9b6Ad7Cf10CB6EEc3",
  ShrincsVerifier: "0xE6F2970bA30d59e8288b7007bA755828372457c3",
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

  it("getShrincsAddresses returns the default entry for BASE_SEPOLIA", () => {
    expect(getShrincsAddresses(84532)).toEqual(NETWORK_ADDRESSES.default);
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
