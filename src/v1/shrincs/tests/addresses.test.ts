// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { getAddress } from "viem";

import { keccak256, toHex } from "viem";

import {
  CANONICAL_ENTRYPOINT_V07,
  NETWORK_ADDRESSES,
  QSALT1_PREFIX,
  deployVaultSalt,
  getShrincsAddresses,
  getShrincsWalletAddress,
  isQSalt1Salt,
  qsalt1VaultId,
} from "../addresses.js";
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

describe("QSalt1 identity codec (byte-exact with Solidity)", () => {
  // Fixed fixture shared with the Solidity golden test
  // (test/ShrincsWallet/behaviors/identity.t.sol).
  const statefulC = `0x${"11".repeat(32)}` as const;
  const statelessC = `0x${"22".repeat(32)}` as const;
  const owner = "0x00000000000000000000000000000000000000AA" as const;

  // The 32-byte vault id for the fixture, pinned. BOTH sides must return this
  // exact value — it is what proves the truncation and the ABI encoding agree.
  const GOLDEN =
    "0x5153616c743187fa095d9004d2c66b2770cce3714f8805f2484e9083e41b0764";

  it("QSALT1_PREFIX is the 6 ASCII bytes of \"QSalt1\"", () => {
    expect(QSALT1_PREFIX).toBe("0x5153616c7431");
  });

  it("qsalt1VaultId matches the cross-language golden", () => {
    expect(qsalt1VaultId(statefulC, statelessC, owner)).toBe(GOLDEN);
  });

  it("qsalt1VaultId is 32 bytes prefixed by QSALT1_PREFIX", () => {
    const id = qsalt1VaultId(statefulC, statelessC, owner);
    expect((id.length - 2) / 2).toBe(32);
    expect(id.slice(0, 14)).toBe(QSALT1_PREFIX);
  });

  it("qsalt1VaultId binds each input", () => {
    const base = qsalt1VaultId(statefulC, statelessC, owner);
    expect(qsalt1VaultId(`0x${"33".repeat(32)}`, statelessC, owner)).not.toBe(base);
    expect(qsalt1VaultId(statefulC, `0x${"44".repeat(32)}`, owner)).not.toBe(base);
    expect(
      qsalt1VaultId(statefulC, statelessC, "0x00000000000000000000000000000000000000bb")
    ).not.toBe(base);
  });

  it("isQSalt1Salt is true for a QSalt1 vault id", () => {
    expect(isQSalt1Salt(GOLDEN)).toBe(true);
    expect(isQSalt1Salt(qsalt1VaultId(statefulC, statelessC, owner))).toBe(true);
  });

  it("isQSalt1Salt is false for a non-prefixed 32-byte value", () => {
    expect(isQSalt1Salt(keccak256(toHex("not-a-qsalt1-salt")))).toBe(false);
    expect(
      isQSalt1Salt("0x0000000000000000000000000000000000000000000000000000000000000001")
    ).toBe(false);
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
