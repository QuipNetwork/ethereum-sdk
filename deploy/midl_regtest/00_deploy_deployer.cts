// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * MIDL Deployer Contract Deployment
 *
 * This script deploys the Deployer contract to MIDL's Bitcoin execution layer.
 * Uses hre.midl.initialize(1) for the deployer wallet (DEPLOYER_PRIVATE_KEY).
 *
 * The deployer address will match the Ethereum mainnet deployer, enabling
 * deterministic cross-chain addresses via CREATE2.
 *
 * After deployment, remaining funds are automatically drained to the operations wallet.
 *
 * Usage:
 * npx hardhat deploy --network midl_regtest --tags Deployer
 */

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import "@nomicfoundation/hardhat-ethers";
import { getBalance } from "@midl/core";
import { getContractAddress } from "@midl/viem";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { EXPECTED_DEPLOYER_NONCE, computeDeployerAddress, drainWallet, printDrainSummary } = require("../../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getMidlEnvironment, midlGetOperationsAddresses, midlDeriveEvmAddress } = require("../../lib/midl.cts");

// Type import for MidlEnvironment
import type { MidlEnvironment } from "../../lib/midl.cts";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  console.log("MIDL Deployer Contract Deployment");
  console.log("==================================");

  // Validate DEPLOYER_PRIVATE_KEY is set
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    throw new Error("DEPLOYER_PRIVATE_KEY must be set in .env file");
  }

  // Get MIDL environment and initialize with deployer wallet (index 1)
  const midl: MidlEnvironment = getMidlEnvironment(hre);
  console.log("Initializing MIDL connection with deployer wallet...");
  await midl.initialize(1);

  // Get the deployer account info
  const account = midl.getAccount();
  const btcAddress = account.address;
  const addressType = account.addressType || "p2wpkh";
  const evmAddress = midl.getEVMAddress();

  // Verify the EVM address matches what we expect from DEPLOYER_PRIVATE_KEY
  const expectedEvmAddress = midlDeriveEvmAddress(process.env.DEPLOYER_PRIVATE_KEY);
  if (evmAddress.toLowerCase() !== expectedEvmAddress.toLowerCase()) {
    throw new Error(
      `Deployer EVM address mismatch!\n` +
      `  Connector: ${evmAddress}\n` +
      `  Expected:  ${expectedEvmAddress}`
    );
  }

  // Get operations wallet addresses
  const operationsAddresses = midlGetOperationsAddresses("regtest");

  console.log(`\nDeployer Wallet:`);
  console.log(`  Bitcoin: ${btcAddress} (${addressType})`);
  console.log(`  EVM:     ${evmAddress}`);

  console.log(`\nOperations Wallet:`);
  if (operationsAddresses) {
    console.log(`  Bitcoin: ${operationsAddresses.btc} (p2wpkh)`);
    console.log(`  EVM:     ${operationsAddresses.evm}`);
  } else {
    console.log(`  (PRIVATE_KEY not set)`);
  }

  // Get current status
  let nonce: number;
  try {
    nonce = await hre.ethers.provider.getTransactionCount(evmAddress);
  } catch (error) {
    console.error("Failed to get nonce from ethers provider, trying direct RPC call...");
    // Fallback: try direct RPC call
    const networkConfig = hre.config.networks.midl_regtest;
    const rpcUrl = networkConfig && "url" in networkConfig ? networkConfig.url : "";
    if (!rpcUrl) {
      throw new Error("Failed to get RPC URL for midl_regtest network");
    }
    const response = await fetch(rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "eth_getTransactionCount",
        params: [evmAddress, "latest"],
        id: 1,
      }),
    });
    const data = await response.json();
    if (data.error) {
      throw new Error(`RPC error: ${data.error.message}`);
    }
    nonce = parseInt(data.result, 16);
  }

  const config = midl.getConfig();
  if (!config) throw new Error("MIDL config not initialized");
  const btcBalanceSats = await getBalance(config, btcAddress);
  const btcBalance = btcBalanceSats / 100_000_000;

  console.log(`\nDeployer Status:`);
  console.log(`  Nonce:   ${nonce} (expected: ${EXPECTED_DEPLOYER_NONCE})`);
  console.log(`  Balance: ${btcBalance} BTC (${btcBalanceSats} sats)`);

  // Compute expected Deployer address from wallet + nonce
  const expectedDeployerAddress = computeDeployerAddress(hre, evmAddress);
  console.log(`  Expected Deployer: ${expectedDeployerAddress}`);

  const existingCode = await hre.ethers.provider.getCode(expectedDeployerAddress);
  if (existingCode !== "0x") {
    console.log(`\nDeployer already deployed at: ${expectedDeployerAddress}`);
    console.log("Skipping deployment.");

    // Still attempt to drain if operations address is provided
    await attemptDrain(hre, evmAddress);
    return;
  }

  // Case 4: nonce > expected + 1 → wallet already used beyond deployment, skip
  if (nonce > EXPECTED_DEPLOYER_NONCE + 1) {
    console.log(`\nWARNING: Nonce is ${nonce}, expected ${EXPECTED_DEPLOYER_NONCE} for deployment.`);
    console.log(`Deployer wallet has been used beyond the deployment transaction.`);
    console.log(`Skipping - use a fresh wallet to deploy to a new chain.`);
    return;
  }

  // Case 3: nonce == expected + 1 → deployment done, just drain
  if (nonce === EXPECTED_DEPLOYER_NONCE + 1) {
    console.log(`\nDeployment transaction already sent (nonce is ${nonce}).`);
    console.log(`Draining remaining funds...`);
    await attemptDrain(hre, evmAddress);
    return;
  }

  // Cases 1 & 2: nonce <= expected → need to deploy
  if (btcBalanceSats === 0) {
    throw new Error(
      `Deployer wallet has no BTC balance.\n` +
        `Fund ${btcAddress} with testnet BTC, or use fundDeployer script.`
    );
  }

  // Deploy Deployer contracts from current nonce through expected nonce
  // Each deployment advances the nonce by 1, and the final one at the expected nonce
  // will be at the deterministic address matching Ethereum mainnet
  let currentNonce = nonce;
  let contractAddress = "";

  while (currentNonce <= EXPECTED_DEPLOYER_NONCE) {
    // Compute expected address for this nonce
    const expectedAddressAtNonce = getContractAddress({
      from: evmAddress as `0x${string}`,
      nonce: BigInt(currentNonce),
    });

    const isTargetNonce = currentNonce === EXPECTED_DEPLOYER_NONCE;

    if (isTargetNonce) {
      console.log(`\nDeploying Deployer at target nonce ${currentNonce}...`);
      console.log(`  Expected address: ${expectedAddressAtNonce}`);
    } else {
      console.log(`\nDeploying Deployer to advance nonce from ${currentNonce} to ${currentNonce + 1}...`);
      console.log(`  (This deployment will be at ${expectedAddressAtNonce})`);
    }

    // Delete existing deployment file to allow fresh deployment
    try {
      await midl.deleteDeployment("Deployer");
    } catch {
      // File doesn't exist, that's fine
    }

    // Deploy Deployer contract
    await midl.deploy("Deployer", { args: [] });
    await midl.execute({ skipEstimateGas: true });

    // Verify the deployment address matches expected
    const deployment = await midl.getDeployment("Deployer");
    if (!deployment) {
      throw new Error(`Deployment failed at nonce ${currentNonce} - no deployment record found`);
    }

    if (deployment.address.toLowerCase() !== expectedAddressAtNonce.toLowerCase()) {
      throw new Error(
        `Deployment address mismatch at nonce ${currentNonce}!\n` +
        `  Expected: ${expectedAddressAtNonce}\n` +
        `  Got:      ${deployment.address}`
      );
    }

    console.log(`  Deployed at: ${deployment.address}`);

    // Verify nonce was advanced
    const newNonce = await hre.ethers.provider.getTransactionCount(evmAddress);
    console.log(`  Nonce advanced to ${newNonce}`);

    if (isTargetNonce) {
      contractAddress = deployment.address;

      // Verify this is the expected deterministic address
      if (contractAddress.toLowerCase() !== expectedDeployerAddress.toLowerCase()) {
        throw new Error(
          `Final Deployer address mismatch!\n` +
          `  Expected: ${expectedDeployerAddress}\n` +
          `  Got:      ${contractAddress}`
        );
      }
    }

    currentNonce = newNonce;
  }

  console.log("\n==================================");
  console.log("Deployer Deployment Complete!");
  console.log("==================================");
  console.log(`Deployer (BTC): ${btcAddress}`);
  console.log(`Deployer (EVM): ${evmAddress}`);
  console.log(`Deployer Contract: ${contractAddress}`);

  // Auto-drain remaining funds to operations wallet
  await attemptDrain(hre, evmAddress);

  console.log("\nNext steps:");
  console.log("1. Deploy WOTSPlus and QuipFactory: npx hardhat deploy --network midl_regtest --tags WOTSPlus,QuipFactory");
};

/**
 * Attempt to drain deployer wallet to operations wallet
 */
async function attemptDrain(
  hre: HardhatRuntimeEnvironment,
  deployerAddress: string
): Promise<void> {
  const operationsAddresses = midlGetOperationsAddresses("regtest");

  if (!operationsAddresses) {
    console.log("\n-----------------------------------");
    console.log("Auto-drain skipped: PRIVATE_KEY not set.");
    console.log("To drain remaining funds, set PRIVATE_KEY and run:");
    console.log("  npx hardhat run scripts/drainDeployer.cts --network midl_regtest");
    return;
  }

  console.log("\n-----------------------------------");
  console.log("Draining remaining funds to operations wallet...");
  console.log(`Operations address: ${operationsAddresses.evm}`);

  const result = await drainWallet(hre, deployerAddress, operationsAddresses.evm, {
    minNonce: EXPECTED_DEPLOYER_NONCE,
    skipIfEmpty: true,
  });

  printDrainSummary(hre, result, deployerAddress, operationsAddresses.evm);
}

export default func;
func.tags = ["Deployer"];
// Only run on MIDL networks
func.skip = async (hre: HardhatRuntimeEnvironment) => {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  return chainId !== 777; // MIDL chain ID
};
