// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { EXPECTED_DEPLOYER_NONCE, drainWallet, printDrainSummary } = require("../../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { midlGetOperationsAddress } = require("../../lib/midl.cts");

// Type import for MidlHRE
import type { MidlHRE } from "../../lib/midl.cts";

/**
 * MIDL Deployer Contract Deployment
 *
 * This script deploys the Deployer contract to MIDL's Bitcoin execution layer.
 * It must be run with DEPLOYER_BTC_MNEMONIC at nonce=1 for deterministic addresses.
 *
 * After deployment, remaining funds are automatically drained to the operations wallet
 * (derived from BTC_MNEMONIC).
 *
 * Usage:
 * npx hardhat deploy --network midl_regtest --tags Deployer
 *
 * Note: The hardhat config must use midl_regtest_deployer config which uses
 * DEPLOYER_BTC_MNEMONIC for this script to work correctly.
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const midlHre = hre as MidlHRE;

  console.log("MIDL Deployer Contract Deployment");
  console.log("==================================");

  // Initialize the MIDL SDK
  console.log("Initializing MIDL connection...");
  await midlHre.midl.initialize();

  // Get both Bitcoin and EVM addresses
  const { address: btcAddress, addressType } = midlHre.midl.getAccount();
  const evmAddress = midlHre.midl.getEVMAddress();
  console.log(`\nDeployer Wallet Addresses:`);
  console.log(`  Bitcoin: ${btcAddress} (${addressType})`);
  console.log(`  EVM:     ${evmAddress}`);

  // Check if already deployed
  const existingDeployer = await midlHre.midl.getDeployment("Deployer");
  if (existingDeployer) {
    console.log(`\nDeployer already deployed at: ${existingDeployer.address}`);
    console.log("Skipping deployment.");

    // Still attempt to drain if operations address is provided
    await attemptDrain(hre, evmAddress);
    return;
  }

  // Check nonce - must be exactly EXPECTED_DEPLOYER_NONCE for deterministic address
  const nonce = await hre.ethers.provider.getTransactionCount(evmAddress);
  console.log(`\nCurrent nonce: ${nonce}`);

  if (nonce > EXPECTED_DEPLOYER_NONCE) {
    throw new Error(
      `CRITICAL ERROR: Nonce is ${nonce}, expected ${EXPECTED_DEPLOYER_NONCE}.\n` +
        `The deployer wallet has already been used. This invalidates deterministic addresses.\n` +
        `You must use a fresh wallet with nonce=${EXPECTED_DEPLOYER_NONCE}.`
    );
  }

  // Check balance
  const balance = await hre.ethers.provider.getBalance(evmAddress);
  console.log(`Balance: ${hre.ethers.formatEther(balance)} ETH`);

  if (balance === 0n) {
    throw new Error(
      "Deployer wallet has no balance.\n" +
        "Fund it with testnet BTC from: https://faucet.regtest.midl.xyz"
    );
  }

  // Deploy placeholder transactions if nonce < EXPECTED_DEPLOYER_NONCE
  for (let i = nonce; i < EXPECTED_DEPLOYER_NONCE; i++) {
    console.log(`\nSending placeholder transaction to advance nonce from ${i} to ${i + 1}...`);
    throw new Error(
      `Nonce is ${i}, expected ${EXPECTED_DEPLOYER_NONCE}. ` +
        `Please send ${EXPECTED_DEPLOYER_NONCE - i} transaction(s) from this wallet to advance the nonce.`
    );
  }

  // Stage Deployer deployment
  console.log("\nStaging Deployer contract deployment...");
  await midlHre.midl.deploy("Deployer", {
    args: [],
  });

  // Execute deployment (commits to Bitcoin)
  console.log("Executing deployment (committing to Bitcoin)...");
  await midlHre.midl.execute();

  // Verify deployment
  const deployerDeployment = await midlHre.midl.getDeployment("Deployer");
  if (!deployerDeployment) {
    throw new Error("Deployer deployment failed - contract not found");
  }

  console.log("\n==================================");
  console.log("Deployer Deployment Complete!");
  console.log("==================================");
  console.log(`Deployer (BTC): ${btcAddress}`);
  console.log(`Deployer (EVM): ${evmAddress}`);
  console.log(`Deployer Contract: ${deployerDeployment.address}`);

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
  const operationsAddress = midlGetOperationsAddress();

  if (!operationsAddress) {
    console.log("\n-----------------------------------");
    console.log("Auto-drain skipped: BTC_MNEMONIC not set.");
    console.log("To drain remaining funds, set BTC_MNEMONIC and run:");
    console.log("  npx hardhat run scripts/drainDeployer.ts --network midl_regtest");
    return;
  }

  console.log("\n-----------------------------------");
  console.log("Draining remaining funds to operations wallet...");
  console.log(`Operations address: ${operationsAddress}`);

  const result = await drainWallet(hre, deployerAddress, operationsAddress, {
    minNonce: EXPECTED_DEPLOYER_NONCE,
    skipIfEmpty: true,
  });

  printDrainSummary(hre, result, deployerAddress, operationsAddress);
}

export default func;
func.tags = ["Deployer"];
// Only run on MIDL networks
func.skip = async (hre: HardhatRuntimeEnvironment) => {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  return chainId !== 777; // MIDL chain ID
};
