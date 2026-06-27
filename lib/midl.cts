// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * MIDL Network Utilities
 *
 * MIDL-specific helpers for Bitcoin execution layer operations.
 * This file is NOT part of the npm package - it's for deployment tooling only.
 */

import type { HardhatRuntimeEnvironment } from "hardhat/types";
import { getPublicKey } from "@noble/secp256k1";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";
import "@midl/hardhat-deploy"; // Augments HardhatRuntimeEnvironment with hre.midl
import * as bitcoin from "bitcoinjs-lib";
import ECPairFactory from "ecpair";
import ecc from "@bitcoinerlab/secp256k1";

// Initialize Bitcoin libraries
const ECPair = ECPairFactory(ecc);
bitcoin.initEccLib(ecc);

// =============================================================================
// Types
// =============================================================================

/**
 * Extended HRE type for MIDL plugin
 */
export interface MidlHRE extends HardhatRuntimeEnvironment {
  midl: {
    /**
     * Initialize with specific account.
     * @param accountIndex - 0 = operations (PRIVATE_KEY), 1 = deployer (DEPLOYER_PRIVATE_KEY)
     */
    initialize: (accountIndex?: number) => Promise<void>;
    getEVMAddress: () => string;
    getAccount: () => { address: string; addressType: string };
    deploy: (name: string, opts: { args?: unknown[]; libraries?: Record<string, string> }) => Promise<void>;
    execute: (opts?: { stateOverride?: any; feeRate?: number; skipEstimateGas?: boolean; withdraw?: any }) => Promise<void>;
    getDeployment: (name: string) => Promise<{ address: string; abi: any } | null>;
    callContract: (name: string, methodName: string, opts: { args?: unknown[]; to?: string; value?: bigint; nonce?: number; gas?: bigint }) => Promise<void>;
    getConfig: () => any;
    getWalletClient: () => Promise<any>;
  };
}

/**
 * Check if HRE has MIDL plugin available
 */
export function hasMidlPlugin(hre: HardhatRuntimeEnvironment): hre is MidlHRE {
  return "midl" in hre && hre.midl !== undefined;
}

// =============================================================================
// Address Derivation
// =============================================================================

/**
 * Derive EVM address from a raw private key
 *
 * MIDL uses the same address derivation as Ethereum:
 * - Both use secp256k1 curve
 * - EVM address = keccak256(uncompressed_public_key)[12:]
 * - Same private key → same public key → same EVM address
 */
export function midlDeriveEvmAddress(privateKey: string): string {
  // Remove 0x prefix if present, parse as hex bytes
  const keyHex = privateKey.startsWith("0x") ? privateKey.slice(2) : privateKey;
  const privateKeyBytes = Uint8Array.from(Buffer.from(keyHex, "hex"));

  // Get uncompressed public key (65 bytes: 0x04 prefix + 32 byte x + 32 byte y)
  const publicKey = getPublicKey(privateKeyBytes, false);

  // Hash public key without the 0x04 prefix (last 64 bytes)
  const hash = keccak_256(publicKey.slice(1));

  // Address is last 20 bytes of hash
  const address = bytesToHex(hash.slice(-20));
  return `0x${address}`;
}

/**
 * Derive Bitcoin P2WPKH address from a raw private key
 *
 * @param privateKey - Hex string private key (with or without 0x prefix)
 * @param network - Bitcoin network ('regtest' | 'testnet' | 'bitcoin')
 * @returns The P2WPKH Bitcoin address
 */
export function midlDeriveBtcAddress(
  privateKey: string,
  network: "regtest" | "testnet" | "bitcoin" = "regtest"
): string {
  const keyHex = privateKey.startsWith("0x") ? privateKey.slice(2) : privateKey;
  const keyPair = ECPair.fromPrivateKey(Buffer.from(keyHex, "hex"));
  const bitcoinNetwork = bitcoin.networks[network];

  const p2wpkh = bitcoin.payments.p2wpkh({
    pubkey: keyPair.publicKey,
    network: bitcoinNetwork,
  });

  if (!p2wpkh.address) {
    throw new Error("Failed to derive Bitcoin address");
  }

  return p2wpkh.address;
}

/**
 * Get the operations wallet addresses from PRIVATE_KEY
 *
 * @returns Both EVM and Bitcoin addresses, or undefined if PRIVATE_KEY not set
 */
export function midlGetOperationsAddresses(
  network: "regtest" | "testnet" | "bitcoin" = "regtest"
): { evm: string; btc: string } | undefined {
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    return undefined;
  }
  return {
    evm: midlDeriveEvmAddress(privateKey),
    btc: midlDeriveBtcAddress(privateKey, network),
  };
}

/**
 * Get the operations wallet EVM address from PRIVATE_KEY
 *
 * @returns The EVM address derived from PRIVATE_KEY, or undefined if not set
 */
export function midlGetOperationsAddress(): string | undefined {
  const privateKey = process.env.PRIVATE_KEY;
  if (!privateKey) {
    return undefined;
  }
  return midlDeriveEvmAddress(privateKey);
}

/**
 * Get the deployer wallet EVM address from DEPLOYER_PRIVATE_KEY
 *
 * @returns The EVM address, or undefined if not set
 */
export function midlGetDeployerAddress(): string | undefined {
  const privateKey = process.env.DEPLOYER_PRIVATE_KEY;
  if (!privateKey) {
    return undefined;
  }
  return midlDeriveEvmAddress(privateKey);
}

// =============================================================================
// MIDL Plugin Helpers
// =============================================================================

/**
 * Initialize MIDL connection and return addresses
 */
export async function midlInitialize(hre: HardhatRuntimeEnvironment): Promise<{
  btcAddress: string;
  btcAddressType: string;
  evmAddress: string;
}> {
  if (!hasMidlPlugin(hre)) {
    throw new Error(
      "MIDL plugin not available. Make sure @midl/hardhat-deploy is installed and configured."
    );
  }

  await hre.midl.initialize();

  const { address: btcAddress, addressType: btcAddressType } = hre.midl.getAccount();
  const evmAddress = hre.midl.getEVMAddress();

  return { btcAddress, btcAddressType, evmAddress };
}

/**
 * Print MIDL wallet addresses
 */
export function midlPrintAddresses(
  label: string,
  btcAddress: string,
  btcAddressType: string,
  evmAddress: string
): void {
  console.log(`\n${label}:`);
  console.log(`  Bitcoin: ${btcAddress} (${btcAddressType})`);
  console.log(`  EVM:     ${evmAddress}`);
}

// =============================================================================
// MIDL Environment Factory
// =============================================================================

/**
 * Interface matching both hre.midl and MidlPrivateKeyEnvironment
 *
 * Multi-key connector usage:
 * - initialize(0) = Operations wallet (PRIVATE_KEY)
 * - initialize(1) = Deployer wallet (DEPLOYER_PRIVATE_KEY)
 */
export interface MidlEnvironment {
  /**
   * Initialize with specific account.
   * @param accountIndex - 0 = operations (PRIVATE_KEY), 1 = deployer (DEPLOYER_PRIVATE_KEY)
   */
  initialize(accountIndex?: number): Promise<void>;
  deploy(name: string, options?: {
    args?: unknown[];
    libraries?: Record<string, string>;
    gas?: bigint;
    to?: string;
    value?: bigint;
    nonce?: number;
  }): Promise<any>;
  callContract(name: string, methodName: string, options: {
    args?: unknown[];
    to?: string;
    value?: bigint;
    nonce?: number;
    gas?: bigint;
  }): Promise<void>;
  execute(options?: {
    stateOverride?: any;
    feeRate?: number;
    skipEstimateGas?: boolean;
    withdraw?: any;
  }): Promise<void>;
  getDeployment(name: string): Promise<{ address: string; abi: any } | null>;
  /** Delete a deployment file to allow redeployment */
  deleteDeployment(name: string): Promise<void>;
  getEVMAddress(): string;
  getAccount(): { address: string; addressType?: string };
  /** Get the underlying MIDL config for use with @midl/core functions */
  getConfig(): any;
  /** Get wallet client for low-level operations */
  getWalletClient(): Promise<any>;
}

/**
 * Get the MIDL environment for deployment.
 *
 * Now uses hre.midl directly since @midl/hardhat-deploy supports customConnector.
 * The customConnector is configured in hardhat.config.cts with fixedSecretKeyPairConnector.
 *
 * @param hre - Hardhat Runtime Environment
 * @returns MIDL environment instance (hre.midl)
 */
export function getMidlEnvironment(
  hre: HardhatRuntimeEnvironment
): MidlEnvironment {
  if (!hasMidlPlugin(hre)) {
    throw new Error(
      "MIDL plugin not available. Make sure @midl/hardhat-deploy is installed and " +
      "midl config is defined in hardhat.config.cts"
    );
  }

  // hre.midl is now properly configured with customConnector from hardhat.config.cts
  return hre.midl as unknown as MidlEnvironment;
}

/**
 * Extended HRE type for getting MIDL environment
 */
export interface MidlEnabledHRE extends HardhatRuntimeEnvironment {
  getMidlEnvironment(networkName?: string): MidlEnvironment;
}
