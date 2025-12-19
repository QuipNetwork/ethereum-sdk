// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { MIDL_CHAIN_ID, loadReleaseBytecode } = require("../../lib/deploy.cts");

/**
 * EVM WOTSPlus Library Deployment
 *
 * This script deploys the WOTSPlus library via the Deployer contract using CREATE2.
 * Uses the stored release bytecode from deployments/bytecode/ to ensure
 * deterministic addresses matching the mainnet deployment.
 *
 * Prerequisites:
 * - Deployer contract must be deployed (run with --tags Deployer first)
 * - PRIVATE_KEY wallet must have funds
 *
 * Usage:
 * npx hardhat deploy --network <network> --tags WOTSPlus
 *
 * Environment:
 * - PRIVATE_KEY: Operations wallet private key
 * - DEPLOYER_ADDRESS: Expected Deployer contract address
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);

  // Skip for MIDL network (uses separate deploy scripts)
  if (chainId === MIDL_CHAIN_ID) {
    console.log("Skipping EVM deploy for MIDL network. Use deploy/midl_regtest/ instead.");
    return;
  }

  console.log("EVM WOTSPlus Library Deployment");
  console.log("================================");
  console.log(`Network: ${network.name} (chainId: ${chainId})`);

  // Validate environment
  if (!process.env.DEPLOYER_ADDRESS) {
    throw new Error("DEPLOYER_ADDRESS must be set in .env file");
  }

  const deployerAddress = process.env.DEPLOYER_ADDRESS;

  // Verify Deployer contract exists
  const deployerCode = await hre.ethers.provider.getCode(deployerAddress);
  if (deployerCode === "0x") {
    throw new Error(
      "Deployer contract not found.\n" +
        "Run deployment with --tags Deployer first."
    );
  }
  console.log(`\nDeployer contract: ${deployerAddress}`);

  // Load WOTSPlus bytecode from release (ensures consistent addresses)
  const wotsRelease = loadReleaseBytecode("WOTSPlus.sol");
  const wotsBytecode = wotsRelease.creationBytecode;
  const expectedAddress = wotsRelease.address;

  console.log(`Using release bytecode for address: ${expectedAddress}`);
  console.log(`Bytecode size: ${(wotsBytecode.length - 2) / 2} bytes`);

  // Check if already deployed
  const existingCode = await hre.ethers.provider.getCode(expectedAddress);
  if (existingCode !== "0x") {
    console.log(`\nWOTSPlus already deployed at: ${expectedAddress}`);
    console.log("Skipping deployment.");
    return;
  }

  // Get signer
  const [signer] = await hre.ethers.getSigners();
  const signerAddress = await signer.getAddress();
  console.log(`\nDeploying from: ${signerAddress}`);

  // Check balance
  const balance = await hre.ethers.provider.getBalance(signerAddress);
  console.log(`Balance: ${hre.ethers.formatEther(balance)} ETH`);

  if (balance === 0n) {
    throw new Error("Wallet has no balance. Please fund it before deploying.");
  }

  // Get Deployer contract instance
  const deployer = await hre.ethers.getContractAt("Deployer", deployerAddress, signer);

  // Deploy WOTSPlus via Deployer contract using stored salt
  console.log("\nDeploying WOTSPlus via Deployer contract...");
  const tx = await deployer.deploy(wotsBytecode, wotsRelease.salt);
  console.log(`Transaction submitted: ${tx.hash}`);
  console.log("Waiting for confirmation...");

  const receipt = await tx.wait();
  if (!receipt) {
    throw new Error("Transaction failed - no receipt");
  }

  // Parse the Deploy event to get the address
  const deployEvent = receipt.logs.find(
    (log) => log.topics[0] === deployer.interface.getEvent("Deploy")?.topicHash
  );

  if (!deployEvent) {
    throw new Error("Deploy event not found in transaction receipt");
  }

  const parsedLog = deployer.interface.parseLog({
    topics: deployEvent.topics,
    data: deployEvent.data,
  });

  const wotsAddress = parsedLog?.args.addr;

  if (wotsAddress !== expectedAddress) {
    console.warn(
      `WARNING: Deployed address ${wotsAddress} doesn't match expected ${expectedAddress}`
    );
  }

  console.log("\n================================");
  console.log("WOTSPlus Deployment Complete!");
  console.log("================================");
  console.log(`WOTSPlus: ${wotsAddress}`);
  console.log(`Gas used: ${receipt.gasUsed}`);
  console.log(`Total cost: ${hre.ethers.formatEther(receipt.gasUsed * receipt.gasPrice)} ETH`);
  console.log("\nNext steps:");
  console.log("1. Deploy QuipFactory: npx hardhat deploy --network " + network.name + " --tags QuipFactory");
};

export default func;
func.tags = ["WOTSPlus"];
func.dependencies = ["Deployer"];
