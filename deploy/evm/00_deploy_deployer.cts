// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { EXPECTED_DEPLOYER_NONCE, MIDL_CHAIN_ID, computeDeployerAddress } = require("../../lib/deploy.cts");


/**
 * EVM Deployer Contract Deployment
 *
 * This script deploys the Deployer contract to EVM networks.
 * It must be run with DEPLOYER_PRIVATE_KEY at nonce=1 for deterministic addresses.
 *
 * After deployment, remaining funds are automatically drained to the operations wallet
 * (derived from PRIVATE_KEY).
 *
 * Usage:
 * npx hardhat deploy --network <network> --tags Deployer
 *
 * Environment:
 * - DEPLOYER_PRIVATE_KEY: One-time deployer wallet private key
 * - DEPLOYER_PUBLIC_KEY: Expected public key (for validation)
 * - PRIVATE_KEY: Operations wallet private key (drain destination)
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);

  console.log("EVM Deployer Contract Deployment");
  console.log("=================================");
  console.log(`Network: ${network.name} (chainId: ${chainId})`);

  // Validate environment
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    throw new Error("DEPLOYER_PRIVATE_KEY must be set in .env file");
  }
  if (!process.env.DEPLOYER_PUBLIC_KEY) {
    throw new Error("DEPLOYER_PUBLIC_KEY must be set in .env file");
  }

  // Create deployer wallet
  const deployer = new hre.ethers.Wallet(
    process.env.DEPLOYER_PRIVATE_KEY!,
    hre.ethers.provider
  );
  const deployerAddress = await deployer.getAddress();

  // Validate deployer address matches expected
  if (process.env.DEPLOYER_PUBLIC_KEY !== deployerAddress) {
    throw new Error(
      `DEPLOYER_PUBLIC_KEY mismatch: got ${deployerAddress}, expected ${process.env.DEPLOYER_PUBLIC_KEY}`
    );
  }

  // Compute expected Deployer address from wallet + nonce
  const expectedDeployerAddress = computeDeployerAddress(hre, deployerAddress);

  console.log(`\nDeployer Wallet: ${deployerAddress}`);
  console.log(`Expected Deployer: ${expectedDeployerAddress}`);

  // Check if Deployer contract already exists
  const existingCode = await hre.ethers.provider.getCode(expectedDeployerAddress);
  if (existingCode !== "0x") {
    console.log(`\nDeployer already deployed at: ${expectedDeployerAddress}`);
    console.log("Skipping deployment.");

    // Still attempt to drain
    await attemptDrain(hre, deployer, deployerAddress);
    return;
  }

  // Check nonce
  const nonce = await hre.ethers.provider.getTransactionCount(deployerAddress);
  console.log(`Current nonce: ${nonce}`);

  if (nonce > EXPECTED_DEPLOYER_NONCE) {
    throw new Error(
      `CRITICAL ERROR: Nonce is ${nonce}, expected ${EXPECTED_DEPLOYER_NONCE}.\n` +
        `The deployer wallet has already been used. This invalidates deterministic addresses.\n` +
        `You must use a fresh wallet with nonce=${EXPECTED_DEPLOYER_NONCE}.`
    );
  }

  // Check balance
  const balance = await hre.ethers.provider.getBalance(deployerAddress);
  console.log(`Balance: ${hre.ethers.formatEther(balance)} ETH`);

  const MIN_BALANCE = hre.ethers.parseEther("0.04");
  if (balance < MIN_BALANCE) {
    throw new Error(
      `Balance too low (${hre.ethers.formatEther(balance)} ETH). ` +
        `Needs at least ${hre.ethers.formatEther(MIN_BALANCE)} ETH.`
    );
  }

  // Deploy placeholder transactions if nonce < EXPECTED_DEPLOYER_NONCE
  for (let i = nonce; i < EXPECTED_DEPLOYER_NONCE; i++) {
    console.log(`\nDeploying placeholder contract to advance nonce from ${i} to ${i + 1}...`);
    const Deployer = await hre.ethers.getContractFactory("Deployer", deployer);
    const placeholderContract = await Deployer.deploy();
    await placeholderContract.waitForDeployment();
    console.log(`Placeholder deployed at: ${await placeholderContract.getAddress()}`);
  }

  // Deploy Deployer contract
  console.log("\nDeploying Deployer contract...");
  const Deployer = await hre.ethers.getContractFactory("Deployer", deployer);
  const deployerContract = await Deployer.deploy();
  const deployReceipt = await deployerContract.waitForDeployment();

  // Get deployment details
  const deployTx = deployReceipt.deploymentTransaction();
  if (!deployTx) throw new Error("Deployment transaction not found");

  const receipt = await deployTx.wait();
  if (!receipt) throw new Error("Failed to get transaction receipt");

  const contractAddress = await deployerContract.getAddress();

  // Validate deployed address matches expected
  if (contractAddress !== expectedDeployerAddress) {
    console.error(
      `WARNING: Deployed address ${contractAddress} doesn't match expected ${expectedDeployerAddress}`
    );
  }

  console.log("\n=================================");
  console.log("Deployer Deployment Complete!");
  console.log("=================================");
  console.log(`Deployer Contract: ${contractAddress}`);
  console.log(`Gas used: ${receipt.gasUsed}`);
  console.log(`Gas price: ${receipt.gasPrice}`);
  console.log(`Total cost: ${hre.ethers.formatEther(receipt.gasUsed * receipt.gasPrice)} ETH`);

  // Auto-drain remaining funds
  await attemptDrain(hre, deployer, deployerAddress);

  console.log("\nNext steps:");
  console.log("1. Deploy WOTSPlus and QuipFactory: npx hardhat deploy --network " + network.name + " --tags WOTSPlus,QuipFactory");
};

/**
 * Attempt to drain deployer wallet to operations wallet
 */
async function attemptDrain(
  hre: HardhatRuntimeEnvironment,
  deployer: import("ethers").Wallet,
  deployerAddress: string
): Promise<void> {
  if (!process.env.PRIVATE_KEY) {
    console.log("\n-----------------------------------");
    console.log("Auto-drain skipped: PRIVATE_KEY not set.");
    console.log("To drain remaining funds, set PRIVATE_KEY and run:");
    console.log("  npx hardhat run scripts/drainDeployer.ts --network <network>");
    return;
  }

  // Get operations wallet address
  const operationsWallet = new hre.ethers.Wallet(process.env.PRIVATE_KEY!);
  const operationsAddress = await operationsWallet.getAddress();

  console.log("\n-----------------------------------");
  console.log("Draining remaining funds to operations wallet...");
  console.log(`Operations address: ${operationsAddress}`);

  // Get balance and check if worth draining
  const balance = await hre.ethers.provider.getBalance(deployerAddress);
  if (balance === 0n) {
    console.log("No funds to drain - deployer wallet is empty.");
    return;
  }

  // Estimate gas
  const gasPrice = await hre.ethers.provider.getFeeData();
  if (!gasPrice.gasPrice) {
    console.log("Failed to get gas price - skipping drain.");
    return;
  }

  const gasLimit = 21000n;
  const gasCost = (gasPrice.gasPrice * gasLimit * 120n) / 100n;
  const amountToSend = balance - gasCost;

  if (amountToSend <= 0n) {
    console.log("Balance too low to cover gas costs - skipping drain.");
    return;
  }

  // Send transaction
  try {
    const tx = await deployer.sendTransaction({
      to: operationsAddress,
      value: amountToSend,
      gasLimit: gasLimit,
      gasPrice: gasPrice.gasPrice,
    });

    const receipt = await tx.wait();
    console.log("\nDrain Complete!");
    console.log(`Amount: ${hre.ethers.formatEther(amountToSend)} ETH`);
    console.log(`Transaction: ${tx.hash}`);
  } catch (error) {
    console.log(`Drain failed: ${error instanceof Error ? error.message : error}`);
  }
}

export default func;
func.tags = ["Deployer"];
// Skip for MIDL networks (uses separate deploy scripts in deploy/midl_regtest/)
func.skip = async (hre) => {
  const network = await hre.ethers.provider.getNetwork();
  return Number(network.chainId) === MIDL_CHAIN_ID;
};
