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
import { UnsupportedNetworkError } from "./errors.js";

/**
 * Network-specific contract address configuration
 */
export interface NetworkAddresses {
  /// Sunset WOTS+-era CREATE3 bootstrap (now `contracts/deprecated/Deployer.sol`).
  /// Kept because the deployed WOTS+-era artifacts derive their addresses from
  /// it; LIVE contracts deploy straight through CreateX with sender-guarded
  /// salts and do not touch it.
  Deployer: Address;
  WOTSPlus: Address;
  /// LIVE WalletFactory ERC-1967 proxy — a sender-guarded CreateX CREATE3
  /// deployment, so its address is a function of (CreateX, DEPLOY_OPERATOR,
  /// salt), identical on every chain reached by the same operator.
  WalletFactory: Address;
  /// WOTSPlusImplementation implementation that the factory clones via CREATE3 on
  /// `createWallet`. The impl itself is never called directly (its
  /// initializers are gated); surfaced so tooling can verify which
  /// implementation is vetted on a given chain.
  WOTSPlusImplementation: Address;
  /// ERC-4337 v0.7 EntryPoint. The canonical address
  /// `0x0000000071727De22E5E9d8BAf0edAc6f37da032` is the same across every
  /// chain where v0.7 is deployed — it's a CREATE2 deployment with a
  /// fixed salt. Per-chain entry exists so alternative deployments (e.g.
  /// MIDL, app-specific bundlers) can override.
  EntryPoint: Address;
  /// Per-chain QuipPaymaster proxy address (user-facing). Zero address
  /// indicates no paymaster is deployed on this chain —
  /// `QuipPaymasterClient` rejects construction against a zero address.
  /// Populated once the paymaster is deployed per-chain (Phase 7
  /// release prep).
  QuipPaymaster: Address;
  /// Bare QuipPaymaster implementation behind the ERC1967 proxy. Inert
  /// by design (`_disableInitializers()` runs in its constructor);
  /// exposed for upgrade-path verification and source-code reconciliation.
  QuipPaymasterImpl: Address;
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

/// Chains that share the deterministic CREATE3 deployment addresses captured
/// under the `default` entry of `NETWORK_ADDRESSES`. Live Quip contracts
/// deploy straight through the CreateX singleton with SENDER-GUARDED salts —
/// addresses depend only on (CreateX, DEPLOY_OPERATOR, salt); the sunset
/// WOTS+-era contracts derive through the deprecated `Deployer`
/// (`contracts/deprecated/Deployer.sol`), depending only on (Deployer, salt).
/// Either way the derivation is chain-independent, so any chain reached by
/// the same operator with the same salts inherits the same addresses. Any
/// chainId not in this list AND not explicitly registered in
/// `NETWORK_ADDRESSES` is rejected by `getNetworkAddresses` with
/// `UnsupportedNetworkError`.
const SHARED_DEPLOYMENT_CHAIN_IDS: ReadonlySet<number> = new Set<number>([
  CHAIN_IDS.ETHEREUM_MAINNET,
  CHAIN_IDS.SEPOLIA,
  CHAIN_IDS.BASE,
  CHAIN_IDS.BASE_SEPOLIA,
  CHAIN_IDS.OPTIMISM,
  CHAIN_IDS.OPTIMISM_SEPOLIA,
]);

/**
 * Network-specific address registry
 * Maps chain IDs to their deployed contract addresses
 */
export const NETWORK_ADDRESSES: Record<number | "default", NetworkAddresses> = {
  // Default: Existing EVM chains (shared deterministic addresses via CREATE3)
  default: {
    Deployer: addresses.Deployer as Address,
    WOTSPlus: addresses.WOTSPlus as Address,
    WalletFactory: addresses.WalletFactory as Address,
    WOTSPlusImplementation: addresses.WOTSPlusImplementation as Address,
    EntryPoint: CANONICAL_ENTRYPOINT_V07,
    QuipPaymaster: addresses.QuipPaymaster as Address,
    QuipPaymasterImpl: addresses.QuipPaymasterImpl as Address,
  },
  // MIDL Testnet (Chain ID 777) — separate deployment lineage with its
  // own Deployer (see deployments/midl/Deployer.json). The wallet /
  // paymaster impl addresses below are placeholders mirroring v1 until
  // an independent MIDL deploy is recorded.
  [CHAIN_IDS.MIDL_TESTNET]: {
    Deployer: "0xA1A3990Ea898123e4B107D0A2f614232bE428Ef1",
    WOTSPlus: "0x742376ec2A8237Ba46E1ACDDfF315f1Ef25E4C0e",
    WalletFactory: "0xE567d318819c067c26fC1E44D04beD2b4FE93BCC",
    WOTSPlusImplementation: "0x81648CBFA79aD8f2c4A59E0DdeA03b1BC8b34cfb",
    EntryPoint: CANONICAL_ENTRYPOINT_V07,
    QuipPaymaster: "0x4A952d592fAe490762f492dC65487eE2B53Ef554",
    QuipPaymasterImpl: "0xeEFb077B9A0B63BA06ce72Ae07E016A9efA82ed7",
  },
};

/**
 * Get contract addresses for a specific network by chain ID.
 *
 * Resolution order:
 *   1. `chainId === undefined` → returns the `default` entry (back-compat
 *      for callers that operate before the chain is detected, e.g.
 *      `getVaultAddress(vaultId)` with no chainId).
 *   2. `chainId` registered in `NETWORK_ADDRESSES` (e.g. MIDL) → that entry.
 *   3. `chainId` in `SHARED_DEPLOYMENT_CHAIN_IDS` → the `default` entry
 *      (mainnet / sepolia / base / op / their L2 testnets all share
 *      CREATE3-deterministic deployment addresses).
 *   4. Otherwise → throws `UnsupportedNetworkError`. This is the difference
 *      from the prior silent fall-through, which would have returned the
 *      mainnet addresses for any chainId outside the supported set.
 *
 * @param chainId - The chain ID of the network (e.g., 777 for MIDL testnet)
 * @returns NetworkAddresses for the specified chain
 * @throws UnsupportedNetworkError when `chainId` is provided and unsupported.
 */
export function getNetworkAddresses(chainId?: number): NetworkAddresses {
  if (chainId === undefined) {
    return NETWORK_ADDRESSES.default;
  }
  if (chainId in NETWORK_ADDRESSES) {
    return NETWORK_ADDRESSES[chainId];
  }
  if (SHARED_DEPLOYMENT_CHAIN_IDS.has(chainId)) {
    return NETWORK_ADDRESSES.default;
  }
  throw new UnsupportedNetworkError(chainId);
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
export const QUIP_FACTORY_ADDRESS = NETWORK_ADDRESSES.default.WalletFactory;

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
  const factory = getNetworkAddresses(chainId).WalletFactory;
  return computeVaultAddress(factory, vaultId);
}

/**
 * Compute a CREATE3 vault address with an explicit factory address.
 *
 * @param factoryAddress - The WalletFactory contract address
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
