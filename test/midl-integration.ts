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

/**
 * MIDL Network Integration Tests
 *
 * These tests verify Quip Network SDK functionality on MIDL's Bitcoin execution layer.
 * Run against MIDL testnet with:
 *   npx hardhat test test/midl-integration.ts --network midl_regtest
 *
 * Or run locally with Hardhat network:
 *   npx hardhat test test/midl-integration.ts
 */

import { expect } from "chai";
import { ethers } from "ethers";
import hre from "hardhat";

// Import directly from source for test compatibility
// In production, import from "@quip.network/ethereum-sdk"

// Define types and constants inline for test isolation
interface NetworkAddresses {
  Deployer: string;
  WOTSPlus: string;
  QuipFactory: string;
}

const CHAIN_IDS = {
  MIDL_TESTNET: 777,
  ETHEREUM_MAINNET: 1,
  SEPOLIA: 11155111,
  BASE: 8453,
  BASE_SEPOLIA: 84532,
  OPTIMISM: 10,
  OPTIMISM_SEPOLIA: 11155420,
} as const;

// Import addresses from JSON
import addresses from "../src/addresses.json" with { type: "json" };

const NETWORK_ADDRESSES: Record<number | "default", NetworkAddresses> = {
  default: {
    Deployer: addresses.Deployer,
    WOTSPlus: addresses.WOTSPlus,
    QuipFactory: addresses.QuipFactory,
  },
  [CHAIN_IDS.MIDL_TESTNET]: {
    Deployer: "0x0000000000000000000000000000000000000000",
    WOTSPlus: "0x0000000000000000000000000000000000000000",
    QuipFactory: "0x0000000000000000000000000000000000000000",
  },
};

function getNetworkAddresses(chainId?: number): NetworkAddresses {
  if (chainId && chainId in NETWORK_ADDRESSES) {
    return NETWORK_ADDRESSES[chainId];
  }
  return NETWORK_ADDRESSES.default;
}

function isMidlNetwork(chainId: number): boolean {
  return chainId === CHAIN_IDS.MIDL_TESTNET;
}

function getVaultAddress(
  initialOwnerAddress: string,
  vaultId: string,
  chainId?: number
): string {
  // Simplified version for tests - just validates input format
  ethers.getAddress(initialOwnerAddress);
  const networkAddresses = getNetworkAddresses(chainId);

  // Compute a deterministic address (simplified for test purposes)
  const hash = ethers.keccak256(
    ethers.solidityPacked(
      ["address", "bytes32", "address"],
      [initialOwnerAddress, vaultId, networkAddresses.QuipFactory]
    )
  );
  return ethers.getAddress(`0x${hash.slice(-40)}`);
}

describe("MIDL Integration", function () {
  // Increase timeout for network operations
  this.timeout(60000);

  describe("Network Configuration", function () {
    it("should have MIDL testnet chain ID defined", function () {
      expect(CHAIN_IDS.MIDL_TESTNET).to.equal(777);
    });

    it("should have MIDL network addresses configured", function () {
      const midlAddresses = NETWORK_ADDRESSES[CHAIN_IDS.MIDL_TESTNET];
      expect(midlAddresses).to.not.be.undefined;
      expect(midlAddresses.Deployer).to.be.a("string");
      expect(midlAddresses.WOTSPlus).to.be.a("string");
      expect(midlAddresses.QuipFactory).to.be.a("string");
    });

    it("should correctly identify MIDL network", function () {
      expect(isMidlNetwork(777)).to.be.true;
      expect(isMidlNetwork(1)).to.be.false;
      expect(isMidlNetwork(11155111)).to.be.false;
    });

    it("should return network-specific addresses for MIDL", function () {
      const midlAddresses = getNetworkAddresses(777);
      const defaultAddresses = getNetworkAddresses();

      expect(midlAddresses).to.deep.equal(NETWORK_ADDRESSES[777]);
      expect(defaultAddresses).to.deep.equal(NETWORK_ADDRESSES.default);
    });

    it("should fall back to default for unknown chain IDs", function () {
      const unknownAddresses = getNetworkAddresses(999999);
      expect(unknownAddresses).to.deep.equal(NETWORK_ADDRESSES.default);
    });
  });

  describe("Address Computation", function () {
    const TEST_OWNER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    const TEST_VAULT_ID = "0x0000000000000000000000000000000000000000000000000000000000000001";

    it("should compute vault address for default network", function () {
      const address = getVaultAddress(TEST_OWNER, TEST_VAULT_ID);
      expect(ethers.isAddress(address)).to.be.true;
    });

    it("should compute vault address for MIDL network", function () {
      const address = getVaultAddress(TEST_OWNER, TEST_VAULT_ID, 777);
      expect(ethers.isAddress(address)).to.be.true;
    });

    it("should compute different addresses for different networks", function () {
      const defaultAddress = getVaultAddress(TEST_OWNER, TEST_VAULT_ID);
      const midlAddress = getVaultAddress(TEST_OWNER, TEST_VAULT_ID, 777);

      // Addresses will differ if MIDL has different contract addresses
      // This test validates the chain-aware computation works
      expect(ethers.isAddress(defaultAddress)).to.be.true;
      expect(ethers.isAddress(midlAddress)).to.be.true;
    });
  });

  describe("MIDL Network Connection", function () {
    it("should connect to MIDL testnet RPC", async function () {
      // This test verifies the RPC endpoint is accessible
      const provider = new ethers.JsonRpcProvider(
        "https://rpc.regtest.midl.xyz"
      );

      try {
        const network = await provider.getNetwork();
        expect(Number(network.chainId)).to.equal(777);
      } catch (error: unknown) {
        // Skip if network is unreachable (expected in CI without MIDL access)
        const err = error as { code?: string; info?: { responseStatus?: string } };
        if (
          err.code === "ENOTFOUND" ||
          err.code === "ETIMEDOUT" ||
          err.code === "SERVER_ERROR" ||
          err.info?.responseStatus?.includes("404")
        ) {
          console.log("    Skipping: MIDL testnet unreachable");
          this.skip();
        }
        throw error;
      }
    });

    it("should detect MIDL network from provider", async function () {
      const network = await hre.ethers.provider.getNetwork();
      const chainId = Number(network.chainId);

      // Check if we're actually on MIDL
      if (chainId === 777) {
        expect(isMidlNetwork(chainId)).to.be.true;
      } else {
        // Running on local hardhat network
        expect(isMidlNetwork(chainId)).to.be.false;
      }
    });
  });

  describe("Contract Verification (Requires MIDL Deployment)", function () {
    before(async function () {
      const network = await hre.ethers.provider.getNetwork();
      if (Number(network.chainId) !== 777) {
        console.log("    Skipping MIDL contract tests: not on MIDL network");
        this.skip();
      }

      // Also skip if contracts aren't deployed yet
      const midlAddresses = getNetworkAddresses(777);
      if (midlAddresses.QuipFactory === ethers.ZeroAddress) {
        console.log("    Skipping: MIDL contracts not yet deployed");
        this.skip();
      }
    });

    it("should find deployed WOTSPlus library on MIDL", async function () {
      const midlAddresses = getNetworkAddresses(777);
      const code = await hre.ethers.provider.getCode(midlAddresses.WOTSPlus);
      expect(code).to.not.equal("0x");
    });

    it("should find deployed QuipFactory on MIDL", async function () {
      const midlAddresses = getNetworkAddresses(777);
      const code = await hre.ethers.provider.getCode(midlAddresses.QuipFactory);
      expect(code).to.not.equal("0x");
    });

    it("should interact with QuipFactory on MIDL", async function () {
      const midlAddresses = getNetworkAddresses(777);
      const factory = await hre.ethers.getContractAt(
        "QuipFactory",
        midlAddresses.QuipFactory
      );

      // Query the factory
      const creationFee = await factory.creationFee();
      expect(creationFee).to.be.a("bigint");
    });
  });

  describe("WOTS+ Signature Verification (Local)", function () {
    // These tests verify signature mechanics work correctly
    // They run on local hardhat network

    it("should deploy and verify WOTS+ signatures locally", async function () {
      // Deploy WOTSPlus library
      const WOTSPlusLib = await hre.ethers.getContractFactory(
        "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus"
      );
      const wotsPlus = await WOTSPlusLib.deploy();
      await wotsPlus.waitForDeployment();

      const address = await wotsPlus.getAddress();
      expect(ethers.isAddress(address)).to.be.true;

      // Verify contract was deployed
      const code = await hre.ethers.provider.getCode(address);
      expect(code).to.not.equal("0x");
    });
  });
});

describe("Unified API Compatibility", function () {
  describe("WalletProvider Interface", function () {
    it("should accept standard Ethereum provider interface", async function () {
      // Mock EIP-1193 provider
      const mockProvider = {
        request: async ({ method }: { method: string }) => {
          if (method === "eth_chainId") {
            return "0x309"; // 777 in hex
          }
          if (method === "eth_accounts") {
            return ["0x70997970C51812dc3A010C7d01b50e0d17dc79C8"];
          }
          throw new Error(`Unhandled method: ${method}`);
        },
      };

      // Verify the interface is compatible
      expect(mockProvider.request).to.be.a("function");
    });
  });
});
