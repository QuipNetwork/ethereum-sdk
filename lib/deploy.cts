// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Shared Deployment Utilities
 *
 * Common helpers for contract deployment across all networks (EVM and MIDL).
 * This file is NOT part of the npm package - it's for deployment tooling only.
 */

import type { HardhatRuntimeEnvironment } from "hardhat/types";
import fs from "fs";
import path from "path";

// =============================================================================
// Constants
// =============================================================================

/** Critical nonce for deterministic Deployer contract address */
export const EXPECTED_DEPLOYER_NONCE = 1;

/** Standard salt for CREATE2 deployments */
export const DEPLOYMENT_SALT = "QUIP";

/** MIDL network chain ID */
export const MIDL_CHAIN_ID = 777;

// =============================================================================
// Network Detection
// =============================================================================

/**
 * Check if currently connected to MIDL network
 */
export async function isMidlNetwork(hre: HardhatRuntimeEnvironment): Promise<boolean> {
  const network = await hre.ethers.provider.getNetwork();
  return Number(network.chainId) === MIDL_CHAIN_ID;
}

/**
 * Get network info for display
 */
export async function getNetworkInfo(hre: HardhatRuntimeEnvironment): Promise<{
  name: string;
  chainId: number;
  isMidl: boolean;
}> {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  return {
    name: chainId === MIDL_CHAIN_ID ? "MIDL Regtest" : network.name,
    chainId,
    isMidl: chainId === MIDL_CHAIN_ID,
  };
}

// =============================================================================
// Address Computation
// =============================================================================

/**
 * Compute CREATE2 address for a contract deployed via Deployer
 */
export async function computeCreate2Address(
  hre: HardhatRuntimeEnvironment,
  deployerAddress: string,
  bytecode: string,
  salt: string
): Promise<string> {
  const hash = hre.ethers.keccak256(
    hre.ethers.solidityPacked(
      ["bytes1", "address", "bytes32", "bytes32"],
      [
        "0xff",
        deployerAddress,
        hre.ethers.id(salt),
        hre.ethers.keccak256(bytecode),
      ]
    )
  );
  return hre.ethers.getAddress(`0x${hash.slice(-40)}`);
}

/**
 * Check if a contract is deployed at an address
 */
export async function isContractDeployed(
  hre: HardhatRuntimeEnvironment,
  address: string
): Promise<boolean> {
  const code = await hre.ethers.provider.getCode(address);
  return code !== "0x";
}

// =============================================================================
// Wallet Operations
// =============================================================================

/**
 * Result of a drain operation
 */
export interface DrainResult {
  success: boolean;
  transactionHash?: string;
  amountTransferred?: bigint;
  gasUsed?: bigint;
  error?: string;
}

/**
 * Drain funds from one wallet to another
 * Works on any EVM-compatible network including MIDL
 */
export async function drainWallet(
  hre: HardhatRuntimeEnvironment,
  fromAddress: string,
  toAddress: string,
  options: {
    /** Minimum nonce required before draining (for deployer wallet safety) */
    minNonce?: number;
    /** Whether to skip if balance is zero (default: true) */
    skipIfEmpty?: boolean;
    /** Gas limit override (default: 21000) */
    gasLimit?: bigint;
    /** Gas price buffer percentage (default: 20) */
    gasPriceBuffer?: number;
  } = {}
): Promise<DrainResult> {
  const {
    minNonce,
    skipIfEmpty = true,
    gasLimit = 21000n,
    gasPriceBuffer = 20,
  } = options;

  // Get current state
  const [nonce, balance] = await Promise.all([
    hre.ethers.provider.getTransactionCount(fromAddress),
    hre.ethers.provider.getBalance(fromAddress),
  ]);

  // Check nonce requirement
  if (minNonce !== undefined && nonce <= minNonce) {
    return {
      success: false,
      error: `Nonce (${nonce}) must be greater than ${minNonce}. Deployer contract must be deployed first.`,
    };
  }

  // Check balance
  if (balance === 0n) {
    if (skipIfEmpty) {
      return {
        success: true,
        amountTransferred: 0n,
        error: "No funds to drain - wallet is empty.",
      };
    }
    return {
      success: false,
      error: "Wallet has no balance.",
    };
  }

  // Estimate gas
  const gasPrice = await hre.ethers.provider.getFeeData();
  if (!gasPrice.gasPrice) {
    return {
      success: false,
      error: "Failed to get gas price",
    };
  }

  const gasCost = (gasPrice.gasPrice * gasLimit * BigInt(100 + gasPriceBuffer)) / 100n;
  const amountToSend = balance - gasCost;

  if (amountToSend <= 0n) {
    return {
      success: false,
      error: `Balance (${hre.ethers.formatEther(balance)} ETH) too low to cover gas costs (${hre.ethers.formatEther(gasCost)} ETH)`,
    };
  }

  // Get signer
  const [signer] = await hre.ethers.getSigners();
  const signerAddress = await signer.getAddress();

  if (signerAddress.toLowerCase() !== fromAddress.toLowerCase()) {
    return {
      success: false,
      error: `Signer address (${signerAddress}) doesn't match source address (${fromAddress})`,
    };
  }

  // Send transaction
  try {
    const tx = await signer.sendTransaction({
      to: toAddress,
      value: amountToSend,
      gasLimit: gasLimit,
      gasPrice: gasPrice.gasPrice,
    });

    const receipt = await tx.wait();
    if (!receipt) {
      return {
        success: false,
        error: "Transaction failed - no receipt",
      };
    }

    return {
      success: true,
      transactionHash: tx.hash,
      amountTransferred: amountToSend,
      gasUsed: receipt.gasUsed,
    };
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Print drain transaction summary
 */
export function printDrainSummary(
  hre: HardhatRuntimeEnvironment,
  result: DrainResult,
  fromAddress: string,
  toAddress: string
): void {
  if (!result.success) {
    console.log(`\nDrain failed: ${result.error}`);
    return;
  }

  if (result.amountTransferred === 0n) {
    console.log(`\nNo funds to drain - deployer wallet is empty.`);
    return;
  }

  console.log("\n-----------------------------------");
  console.log("Drain Complete!");
  console.log("-----------------------------------");
  console.log(`From:        ${fromAddress}`);
  console.log(`To:          ${toAddress}`);
  console.log(`Amount:      ${hre.ethers.formatEther(result.amountTransferred!)} ETH`);
  console.log(`Gas used:    ${result.gasUsed}`);
  console.log(`Transaction: ${result.transactionHash}`);
}

// =============================================================================
// Release Bytecode Loading
// =============================================================================

/** Directory containing release bytecode files */
const BYTECODE_DIR = path.join(__dirname, "../deployments/bytecode");

/**
 * Release bytecode information loaded from deployments/bytecode/
 */
export interface ReleaseBytecode {
  address: string;
  creationBytecode: string;
  deployedBytecode: string;
  salt: string;
  deployer: string;
  linkedLibraries?: Record<string, string>;
  constructorArgs?: Record<string, string>;
}

/**
 * Load the latest release bytecode for a contract
 *
 * @param contractName - Contract directory name (e.g., "WOTSPlus.sol", "QuipFactory.sol")
 * @returns Release bytecode information
 * @throws Error if release files not found
 */
export function loadReleaseBytecode(contractName: string): ReleaseBytecode {
  const latestPath = path.join(BYTECODE_DIR, contractName, "latest.json");

  if (!fs.existsSync(latestPath)) {
    throw new Error(`Release not found: ${latestPath}\nRun 'npm run release' to generate bytecode.`);
  }

  const latest = JSON.parse(fs.readFileSync(latestPath, "utf-8"));
  const releasePath = path.join(BYTECODE_DIR, contractName, latest.file);

  if (!fs.existsSync(releasePath)) {
    throw new Error(`Release file not found: ${releasePath}`);
  }

  const release = JSON.parse(fs.readFileSync(releasePath, "utf-8"));

  return {
    address: release.address,
    creationBytecode: release.creationBytecode,
    deployedBytecode: release.deployedBytecode,
    salt: release.salt,
    deployer: release.deployer,
    linkedLibraries: release.linkedLibraries,
    constructorArgs: release.constructorArgs,
  };
}

/**
 * Get the expected address from release for a contract
 */
export function getReleaseAddress(contractName: string): string {
  const latestPath = path.join(BYTECODE_DIR, contractName, "latest.json");

  if (!fs.existsSync(latestPath)) {
    throw new Error(`Release not found: ${latestPath}`);
  }

  const latest = JSON.parse(fs.readFileSync(latestPath, "utf-8"));
  return latest.address;
}
