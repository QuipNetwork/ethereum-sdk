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
  getCreate2Address,
  getCreateAddress,
} from "viem";
import addresses from "./addresses.json" with { type: "json" };

/**
 * Network-specific contract address configuration
 */
export interface NetworkAddresses {
  Deployer: Address;
  WOTSPlus: Address;
  QuipFactory: Address;
  /// ERC-4337 v0.7 EntryPoint. The canonical address
  /// `0x0000000071727De22E5E9d8BAf0edAc6f37da032` is the same across every
  /// chain where v0.7 is deployed — it's a CREATE2 deployment with a
  /// fixed salt. Per-chain entry exists so alternative deployments (e.g.
  /// MIDL, app-specific bundlers) can override.
  EntryPoint: Address;
  /// Per-chain QuipPaymaster deployment. Zero address indicates no
  /// paymaster is deployed on this chain — `QuipPaymasterClient` rejects
  /// construction against a zero address. Populated once the paymaster
  /// is deployed per-chain (Phase 7 release prep).
  QuipPaymaster: Address;
}

/// Canonical ERC-4337 v0.7 EntryPoint address. Same on every mainnet /
/// L2 where v0.7 has been deployed (CREATE2 with fixed salt). Override
/// per-chain in `NETWORK_ADDRESSES` for chains with non-canonical
/// deployments.
export const CANONICAL_ENTRYPOINT_V07: Address =
  "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

/**
 * Chain IDs for supported networks
 */
export const CHAIN_IDS = {
  MIDL_TESTNET: 777,
  ETHEREUM_MAINNET: 1,
  SEPOLIA: 11155111,
  BASE: 8453,
  BASE_SEPOLIA: 84532,
  OPTIMISM: 10,
  OPTIMISM_SEPOLIA: 11155420,
} as const;

/**
 * Network-specific address registry
 * Maps chain IDs to their deployed contract addresses
 */
export const NETWORK_ADDRESSES: Record<number | "default", NetworkAddresses> = {
  // Default: Existing EVM chains (shared deterministic addresses via CREATE2)
  default: {
    Deployer: addresses.Deployer as Address,
    WOTSPlus: addresses.WOTSPlus as Address,
    QuipFactory: addresses.QuipFactory as Address,
    EntryPoint: CANONICAL_ENTRYPOINT_V07,
    QuipPaymaster: "0x0000000000000000000000000000000000000000",
  },
  // MIDL Testnet (Chain ID 777) - different deployment mechanism
  // These addresses will be populated after MIDL deployment
  [CHAIN_IDS.MIDL_TESTNET]: {
    Deployer: "0x0000000000000000000000000000000000000000",
    WOTSPlus: "0x0000000000000000000000000000000000000000",
    QuipFactory: "0x0000000000000000000000000000000000000000",
    EntryPoint: CANONICAL_ENTRYPOINT_V07,
    QuipPaymaster: "0x0000000000000000000000000000000000000000",
  },
};

/**
 * Get contract addresses for a specific network by chain ID
 * Falls back to default addresses for standard EVM chains
 *
 * @param chainId - The chain ID of the network (e.g., 777 for MIDL testnet)
 * @returns NetworkAddresses for the specified chain
 */
export function getNetworkAddresses(chainId?: number): NetworkAddresses {
  if (chainId && chainId in NETWORK_ADDRESSES) {
    return NETWORK_ADDRESSES[chainId];
  }
  return NETWORK_ADDRESSES.default;
}

/**
 * Check if a chain ID represents the MIDL network
 */
export function isMidlNetwork(chainId: number): boolean {
  return chainId === CHAIN_IDS.MIDL_TESTNET;
}

// Backwards-compatible exports (use default addresses for existing integrations)
export const DEPLOYER_ADDRESS = NETWORK_ADDRESSES.default.Deployer;
export const WOTS_PLUS_ADDRESS = NETWORK_ADDRESSES.default.WOTSPlus;
export const QUIP_FACTORY_ADDRESS = NETWORK_ADDRESSES.default.QuipFactory;

// Solady CREATE3 proxy initcode hash: keccak256(0x67363d3d37363d34f03d5260086018f3)
const PROXY_INITCODE_HASH: Hex =
  "0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f";

/**
 * Compute the deterministic CREATE3 address of a Quip Vault.
 * The address depends only on (factory, vaultId).
 *
 * @param vaultId - The vault identifier (used as CREATE3 salt)
 * @param chainId - Optional chain ID for network-specific factory resolution
 * @returns The address where the vault contract would be deployed
 */
export function getVaultAddress(vaultId: Hex, chainId?: number): Address {
  const factory = getNetworkAddresses(chainId).QuipFactory;
  return computeVaultAddress(factory, vaultId);
}

/**
 * Compute a CREATE3 vault address with an explicit factory address.
 *
 * @param factoryAddress - The QuipFactory contract address
 * @param vaultId - The vault identifier (used as CREATE3 salt)
 * @returns The address where the vault contract would be deployed
 */
export function computeVaultAddress(
  factoryAddress: Address,
  vaultId: Hex
): Address {
  // CREATE3 Step 1: Proxy address via CREATE2 (fixed proxy bytecode)
  const proxyAddress = getCreate2Address({
    from: factoryAddress,
    salt: vaultId,
    bytecodeHash: PROXY_INITCODE_HASH,
  });

  // CREATE3 Step 2: Final address via CREATE (proxy nonce = 1)
  return getCreateAddress({ from: proxyAddress, nonce: 1n });
}
