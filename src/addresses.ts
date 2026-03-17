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
  getAddress,
  concat,
  encodeAbiParameters,
  encodePacked,
  keccak256,
  toHex,
} from "viem";
import addresses from "./addresses.json" with { type: "json" };
import bytecodeData from "./bytecode.json" with { type: "json" };

/**
 * Network-specific contract address configuration
 */
export interface NetworkAddresses {
  Deployer: Address;
  WOTSPlus: Address;
  QuipFactory: Address;
}

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
  },
  // MIDL Testnet (Chain ID 777) - different deployment mechanism
  // These addresses will be populated after MIDL deployment
  [CHAIN_IDS.MIDL_TESTNET]: {
    Deployer: "0x0000000000000000000000000000000000000000",
    WOTSPlus: "0x0000000000000000000000000000000000000000",
    QuipFactory: "0x0000000000000000000000000000000000000000",
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

/**
 * getVaultAddress computes the deterministic address of a Quip Vault
 * based on the owner and vault ID using the public factory and library addresses.
 *
 * This uses CREATE2 to calculate the same address that would be
 * deployed by the QuipFactory.
 *
 * @param initialOwnerAddress - The Ethereum address of the initial vault owner
 * @param vaultId - The unique identifier for this vault as a hex string
 * @param chainId - Optional chain ID for network-specific address resolution
 * @returns The Ethereum address where the vault contract would be deployed
 */
export function getVaultAddress(
  initialOwnerAddress: Address,
  vaultId: Hex,
  chainId?: number
): Address {
  const addrs = getNetworkAddresses(chainId);
  return computeVaultAddress(
    initialOwnerAddress,
    vaultId,
    addrs.WOTSPlus,
    addrs.QuipFactory
  );
}

/**
 * computeVaultAddress allows calculating a vault address with custom contract addresses
 * @param initialOwnerAddress - The Ethereum address of the initial vault owner
 * @param vaultId - The unique identifier for this vault
 * @param wotsLibraryAddress - The address of the WOTSPlus library contract
 * @param quipFactoryAddress - The address of the QuipFactory contract
 * @returns The Ethereum address where the vault contract would be deployed
 */
export function computeVaultAddress(
  initialOwnerAddress: string,
  vaultId: string | Uint8Array,
  wotsLibraryAddress: string,
  quipFactoryAddress: string
): Address {
  const owner = getAddress(initialOwnerAddress);
  const factory = getAddress(quipFactoryAddress);

  // Ensure vaultId is properly formatted as bytes32
  const vaultIdHex: Hex =
    vaultId instanceof Uint8Array
      ? toHex(vaultId)
      : vaultId.startsWith("0x")
        ? (vaultId as Hex)
        : (`0x${vaultId}` as Hex);

  // Create the initialization code exactly as in the contract
  const creationCode = concat([
    quipWalletCreationCode,
    encodeAbiParameters(
      [{ type: "address" }, { type: "address" }],
      [factory, owner]
    ),
  ]);

  // Compute the CREATE2 address using the same formula as in the contract
  const hash = keccak256(
    encodePacked(
      ["bytes1", "address", "bytes32", "bytes32"],
      ["0xff", factory, vaultIdHex, keccak256(creationCode)]
    )
  );

  // Convert the last 20 bytes of the hash to an address
  return getAddress(`0x${hash.slice(-40)}`);
}

const quipWalletCreationCode: Hex = bytecodeData.quipWalletCreationCode as Hex;
