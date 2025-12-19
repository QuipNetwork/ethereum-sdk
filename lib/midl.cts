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
import { mnemonicToAccount } from "@midl/viem";

// =============================================================================
// Types
// =============================================================================

/**
 * Extended HRE type for MIDL plugin
 */
export interface MidlHRE extends HardhatRuntimeEnvironment {
  midl: {
    initialize: () => Promise<void>;
    getEVMAddress: () => string;
    getAccount: () => { address: string; addressType: string };
    deploy: (name: string, opts: { args?: unknown[]; libraries?: Record<string, string> }) => Promise<void>;
    execute: () => Promise<void>;
    getDeployment: (name: string) => Promise<{ address: string } | null>;
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
 * Derive EVM address from a BTC mnemonic
 *
 * MIDL uses a deterministic derivation from Bitcoin mnemonics to EVM addresses.
 * This uses the same derivation as the MIDL SDK.
 */
export function midlDeriveEvmAddress(mnemonic: string): string {
  const account = mnemonicToAccount(mnemonic);
  return account.address;
}

/**
 * Get the operations wallet EVM address from BTC_MNEMONIC
 *
 * @returns The EVM address derived from BTC_MNEMONIC, or undefined if not set
 */
export function midlGetOperationsAddress(): string | undefined {
  const mnemonic = process.env.BTC_MNEMONIC;
  if (!mnemonic) {
    return undefined;
  }
  return midlDeriveEvmAddress(mnemonic);
}

/**
 * Get the deployer wallet EVM address from DEPLOYER_BTC_MNEMONIC
 *
 * @returns The EVM address derived from DEPLOYER_BTC_MNEMONIC, or undefined if not set
 */
export function midlGetDeployerAddress(): string | undefined {
  const mnemonic = process.env.DEPLOYER_BTC_MNEMONIC;
  if (!mnemonic) {
    return undefined;
  }
  return midlDeriveEvmAddress(mnemonic);
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
