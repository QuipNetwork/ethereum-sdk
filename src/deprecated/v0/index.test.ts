// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Smoke test for the vendored v0 SDK surface. The v0 stack itself was
// validated under @quip.network/ethereum-sdk@0.1.7 — this test only
// verifies that the vendoring + import-path rewrites under src/v0/
// didn't break the barrel.
//
// v0 is frozen (maintenance-only); we deliberately do not mirror v1's
// tests/ layout here — one co-located smoke is enough.
import * as v0 from "./index.js";

describe("v0 barrel exposes legacy surface", () => {
  test("core clients are exported as constructors", () => {
    expect(typeof v0.QuipSigner).toBe("function");
    expect(typeof v0.QuipWalletClient).toBe("function");
    expect(typeof v0.QuipClient).toBe("function");
  });

  test("typechain factories are exported", () => {
    expect(typeof v0.QuipWallet__factory).toBe("function");
    expect(typeof v0.QuipFactory__factory).toBe("function");
    // QuipWallet__factory carries a typechain-shaped `.connect`/`.abi`.
    expect(typeof v0.QuipWallet__factory.connect).toBe("function");
    expect(Array.isArray(v0.QuipWallet__factory.abi)).toBe(true);
  });

  test("network constants and helpers reachable", () => {
    expect(v0.SUPPORTED_NETWORKS.MAINNET).toBe("mainnet");
    expect(v0.SUPPORTED_NETWORKS.SEPOLIA).toBe("sepolia");
    expect(v0.CHAIN_IDS.ETHEREUM_MAINNET).toBe(1);
    expect(typeof v0.computeVaultAddress).toBe("function");
    expect(typeof v0.getNetworkAddresses).toBe("function");
  });

  test("legacy constants are present", () => {
    expect(v0.WOTSPLUS_GAS_ESTIMATE).toBe(850_000);
    expect(v0.DEFAULT_CONFIRMATIONS).toBe(1);
    expect(v0.ERRORS).toBeDefined();
  });
});

describe("QuipClient guards chains with no QuipFactory", () => {
  // Minimal EIP-1193 stub: answers only the calls QuipClient makes during
  // initialization (account lookup, chain id). No network.
  const makeProvider = (chainIdHex: string): v0.WalletProvider => ({
    request: async ({ method }) => {
      switch (method) {
        case "eth_chainId":
          return chainIdHex;
        case "net_version":
          return String(Number.parseInt(chainIdHex, 16));
        case "eth_accounts":
        case "eth_requestAccounts":
          return ["0x00000000000000000000000000000000000000aa"];
        default:
          return null;
      }
    },
  });

  test("rejects on MIDL testnet (777), where the QuipFactory is the zero address", async () => {
    // 777 == 0x309. v0 marks MIDL with a zero QuipFactory: WOTS+ was never
    // deployed there, so no address-compatible wallet can exist.
    await expect(v0.QuipClient.create(makeProvider("0x309"))).rejects.toThrow(
      /not supported on chain 777/
    );
  });

  test("initializes on a chain with a deployed QuipFactory", async () => {
    // 1 == 0x1. Mainnet resolves to a non-zero QuipFactory, so the guard
    // does not fire and the client constructs.
    const client = await v0.QuipClient.create(makeProvider("0x1"));
    expect(client.getChainId()).toBe(1);
  });
});
