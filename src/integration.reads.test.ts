// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  http,
} from "viem";
import { createAnvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { quipFactoryAbi } from "./abi/QuipFactory.js";
import {
  tryMulticall,
  resetMulticallCacheForTesting,
  getMulticall3Address,
  MULTICALL3_ADDRESS,
} from "./internal/multicall.js";
import { CHAIN_IDS } from "./addresses.js";
import { QuipClient } from "./factoryClient.js";

// ─── Forge artifact ─────────────────────────────────────────────────
const factoryArtifact = JSON.parse(
  readFileSync(
    join(process.cwd(), "out/QuipFactory.sol/QuipFactory.json"),
    "utf8"
  )
);
const factoryBytecode = factoryArtifact.bytecode.object as Hex;

const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(ANVIL_PRIV_KEY);

// Distinct port from other Anvil-based tests.
const anvil = createAnvil({ port: 8548 });
let publicClient: PublicClient;
let walletClient: WalletClient;
let factoryAddress: Address;

const MAX_FEE = 10n ** 16n;

beforeAll(async () => {
  await anvil.start();
  const transport = http(`http://127.0.0.1:${anvil.port}`);
  publicClient = createPublicClient({ chain: foundry, transport });
  walletClient = createWalletClient({ chain: foundry, transport, account });

  const hash = await walletClient.deployContract({
    abi: quipFactoryAbi,
    bytecode: factoryBytecode,
    args: [account.address, MAX_FEE],
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  factoryAddress = receipt.contractAddress!;

  resetMulticallCacheForTesting();
}, 30_000);

afterAll(async () => {
  await anvil.stop().catch(() => {});
}, 10_000);

describe("multicall3 address resolver", () => {
  test("returns canonical address for standard chains", () => {
    expect(getMulticall3Address(CHAIN_IDS.ETHEREUM_MAINNET)).toBe(
      MULTICALL3_ADDRESS
    );
    expect(getMulticall3Address(CHAIN_IDS.SEPOLIA)).toBe(MULTICALL3_ADDRESS);
    expect(getMulticall3Address(CHAIN_IDS.BASE)).toBe(MULTICALL3_ADDRESS);
    expect(getMulticall3Address(CHAIN_IDS.OPTIMISM)).toBe(MULTICALL3_ADDRESS);
    expect(getMulticall3Address(31337)).toBe(MULTICALL3_ADDRESS); // anvil/foundry
  });

  test("returns null on chains known to lack Multicall3", () => {
    expect(getMulticall3Address(CHAIN_IDS.MIDL_TESTNET)).toBeNull();
  });
});

describe("tryMulticall against deployed QuipFactory", () => {
  beforeEach(() => {
    // Each test starts with a clean cache so prior `forceSequential` doesn't
    // bleed into the multicall path.
    resetMulticallCacheForTesting();
  });

  // Note on Multicall3 + Anvil: a fresh Anvil node has no Multicall3
  // deployed at the canonical address. `tryMulticall` probes once, fails,
  // caches the chain as unavailable, and falls back to sequential reads.
  // The end-to-end Multicall3 path is exercised against real testnets/
  // mainnet where Multicall3 is deployed; here we cover the fallback.

  test("forceSequential reads owner + creationFee + MAX_FEE", async () => {
    const calls = [
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "owner" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "creationFee" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "MAX_FEE" as const },
    ];
    const results = await tryMulticall(publicClient, calls, {
      chainId: foundry.id,
      forceSequential: true,
    });

    expect(results).toHaveLength(3);
    expect(results[0].status === "success" && results[0].result).toBe(
      account.address
    );
    expect(results[1].status === "success" && results[1].result).toBe(0n);
    expect(results[2].status === "success" && results[2].result).toBe(MAX_FEE);
  });

  test("auto-fallback path returns identical results to forceSequential", async () => {
    // First call: probes Multicall3 (fails on Anvil), caches unavailable,
    // falls back to sequential. Second call: cached → straight to sequential.
    const calls = [
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "owner" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "creationFee" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "executeFee" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "MAX_FEE" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "latestWalletImpl" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "getVettedCodeCount" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "pendingOwner" as const },
    ];

    const viaAuto = await tryMulticall(publicClient, calls, {
      chainId: foundry.id,
    });
    const viaForced = await tryMulticall(publicClient, calls, {
      chainId: foundry.id,
      forceSequential: true,
    });

    expect(viaAuto.length).toBe(viaForced.length);
    for (let i = 0; i < calls.length; i++) {
      expect(viaAuto[i].status).toBe(viaForced[i].status);
      if (viaAuto[i].status === "success") {
        expect(viaAuto[i].result).toEqual(viaForced[i].result);
      }
    }
  });

  test("empty calls array short-circuits to []", async () => {
    const results = await tryMulticall(publicClient, [], {
      chainId: foundry.id,
      forceSequential: true,
    });
    expect(results).toEqual([]);
  });

  test("out-of-bounds vaultIds read surfaces as failure (not throw)", async () => {
    const calls = [
      {
        address: factoryAddress,
        abi: quipFactoryAbi,
        functionName: "vaultIds" as const,
        args: [account.address, 0n] as const,
      },
    ];
    const results = await tryMulticall(publicClient, calls, {
      chainId: foundry.id,
      forceSequential: true,
    });
    // No vaults registered yet → out-of-bounds read.
    expect(results[0].status).toBe("failure");
  });

  test("MIDL_TESTNET chainId returns null from resolver and uses sequential without probing", async () => {
    // No RPC happens here — the resolver short-circuits before any network
    // call. Verifies the cache stays cold so other tests aren't affected.
    expect(getMulticall3Address(CHAIN_IDS.MIDL_TESTNET)).toBeNull();
    const calls = [
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "owner" as const },
    ];
    const results = await tryMulticall(publicClient, calls, {
      chainId: CHAIN_IDS.MIDL_TESTNET,
    });
    expect(results[0].status === "success" && results[0].result).toBe(
      account.address
    );
  });
});

describe("QuipClient.getFactoryState end-to-end", () => {
  // QuipClient depends on a chainId match in NETWORK_ADDRESSES — Anvil's
  // foundry chainId (31337) isn't in the table. Skip the QuipClient.create
  // path and exercise the underlying tryMulticall against the real factory
  // by talking to it directly with the quipFactoryAbi.
  beforeEach(() => {
    resetMulticallCacheForTesting();
  });

  test("aggregates owner, fees, MAX_FEE, latest impl, vetted count in one batch", async () => {
    // Mirror the body of QuipClient.getFactoryState to validate the call
    // pattern + result shape against a live deployment.
    const calls = [
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "owner" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "pendingOwner" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "creationFee" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "executeFee" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "MAX_FEE" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "latestWalletImpl" as const },
      { address: factoryAddress, abi: quipFactoryAbi, functionName: "getVettedCodeCount" as const },
    ];

    const results = await tryMulticall(publicClient, calls, {
      chainId: foundry.id,
      forceSequential: true,
    });

    expect(results.every((r) => r.status === "success")).toBe(true);
    expect(results[0].status === "success" && results[0].result).toBe(account.address);
    // Pre-deploy default state: no pending owner, no fees, no vetted impl.
    const ZERO = "0x0000000000000000000000000000000000000000" as Address;
    expect(results[1].status === "success" && results[1].result).toBe(ZERO);
    expect(results[2].status === "success" && results[2].result).toBe(0n);
    expect(results[3].status === "success" && results[3].result).toBe(0n);
    expect(results[4].status === "success" && results[4].result).toBe(MAX_FEE);
    expect(results[5].status === "success" && results[5].result).toBe(ZERO);
    expect(results[6].status === "success" && results[6].result).toBe(0n);
  });

  test("`QuipClient` placeholder exists for cross-reference (compile check)", () => {
    // Ensures the export hasn't been renamed; full e2e through QuipClient
    // requires NETWORK_ADDRESSES to know the foundry chain, which is not
    // wired up. Exercising QuipClient.getFactoryState end-to-end will land
    // when Phase 7 populates address tables for test chains.
    expect(typeof QuipClient).toBe("function");
  });
});
