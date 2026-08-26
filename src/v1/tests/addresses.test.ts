// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type Address, type Hex, getAddress, keccak256, toHex } from "viem";

import {
  CANONICAL_ENTRYPOINT_V07,
  CHAIN_IDS,
  NETWORK_ADDRESSES,
  computeVaultAddress,
  getNetworkAddresses,
  getVaultAddress,
  isMidlNetwork,
} from "../addresses.js";
import { UnsupportedNetworkError } from "../errors.js";

const FACTORY = "0xE567d318819c067c26fC1E44D04beD2b4FE93BCC" as Address;
const salt = (s: string): Hex => keccak256(toHex(new TextEncoder().encode(s)));

describe("getNetworkAddresses", () => {
  it("returns the default entry when chainId is omitted", () => {
    expect(getNetworkAddresses()).toBe(NETWORK_ADDRESSES.default);
  });

  it("returns the registered entry for MIDL testnet", () => {
    expect(getNetworkAddresses(CHAIN_IDS.MIDL_TESTNET)).toBe(
      NETWORK_ADDRESSES[CHAIN_IDS.MIDL_TESTNET]
    );
  });

  it("returns the default entry for shared CREATE3 chains", () => {
    for (const chainId of [
      CHAIN_IDS.ETHEREUM_MAINNET,
      CHAIN_IDS.SEPOLIA,
      CHAIN_IDS.BASE,
      CHAIN_IDS.BASE_SEPOLIA,
      CHAIN_IDS.OPTIMISM,
      CHAIN_IDS.OPTIMISM_SEPOLIA,
    ]) {
      expect(getNetworkAddresses(chainId)).toBe(NETWORK_ADDRESSES.default);
    }
  });

  it("throws UnsupportedNetworkError for an unknown chain id", () => {
    expect(() => getNetworkAddresses(999999)).toThrow(UnsupportedNetworkError);
  });

  it("carries the offending chainId on the error", () => {
    try {
      getNetworkAddresses(999999);
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(UnsupportedNetworkError);
      expect((e as UnsupportedNetworkError).message).toContain("999999");
    }
  });
});

describe("default network entry", () => {
  it("exposes the shared fields", () => {
    const d = NETWORK_ADDRESSES.default;
    expect(d.EntryPoint).toBe(CANONICAL_ENTRYPOINT_V07);
    expect(getAddress(d.WalletFactory)).toBe(d.WalletFactory);
  });

  it("exposes the WOTS+ superset fields for the deprecated family", () => {
    const d = NETWORK_ADDRESSES.default;
    for (const field of [
      d.Deployer,
      d.WOTSPlus,
      d.WOTSPlusImplementation,
      d.QuipPaymaster,
      d.QuipPaymasterImpl,
    ]) {
      expect(getAddress(field)).toBe(field); // valid checksummed address
    }
  });
});

describe("isMidlNetwork", () => {
  it("is true only for the MIDL testnet chain id", () => {
    expect(isMidlNetwork(CHAIN_IDS.MIDL_TESTNET)).toBe(true);
    expect(isMidlNetwork(CHAIN_IDS.ETHEREUM_MAINNET)).toBe(false);
    expect(isMidlNetwork(CHAIN_IDS.BASE)).toBe(false);
  });
});

describe("computeVaultAddress / getVaultAddress", () => {
  it("is deterministic for the same (factory, vaultId)", () => {
    const id = salt("vault-a");
    expect(computeVaultAddress(FACTORY, id)).toBe(computeVaultAddress(FACTORY, id));
  });

  it("produces distinct addresses for distinct vaultIds", () => {
    expect(computeVaultAddress(FACTORY, salt("vault-a"))).not.toBe(
      computeVaultAddress(FACTORY, salt("vault-b"))
    );
  });

  it("depends on the factory address", () => {
    const id = salt("vault-a");
    const otherFactory =
      "0xb84a596A6fB567FC4634b4f49212410D1193140e" as Address;
    expect(computeVaultAddress(FACTORY, id)).not.toBe(
      computeVaultAddress(otherFactory, id)
    );
  });

  it("returns a valid checksummed address", () => {
    const addr = computeVaultAddress(FACTORY, salt("vault-a"));
    expect(getAddress(addr)).toBe(addr);
  });

  it("getVaultAddress delegates to the resolved factory", () => {
    const id = salt("vault-a");
    const expected = computeVaultAddress(
      NETWORK_ADDRESSES.default.WalletFactory,
      id
    );
    expect(getVaultAddress(id)).toBe(expected);
    expect(getVaultAddress(id, CHAIN_IDS.BASE)).toBe(expected);
  });
});
