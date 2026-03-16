// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import fs from "fs";
import path from "path";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { MIDL_CHAIN_ID, loadReleaseBytecode, getReleaseAddress } = require("../../lib/deploy.cts");

/**
 * EVM QuipFactory Deployment
 *
 * This script deploys the QuipFactory contract via the Deployer contract using CREATE2.
 * Uses the stored release bytecode from deployments/bytecode/ to ensure
 * deterministic addresses matching the mainnet deployment.
 *
 * Note: The release bytecode includes constructor args (initialOwner, wotsLibrary)
 * baked in from the mainnet deployment. This ensures the same address across all chains.
 *
 * Prerequisites:
 * - Deployer contract must be deployed (run with --tags Deployer first)
 * - WOTSPlus library must be deployed (run with --tags WOTSPlus first)
 * - PRIVATE_KEY wallet must have funds
 *
 * Usage:
 * npx hardhat deploy --network <network> --tags QuipFactory
 *
 * Environment:
 * - PRIVATE_KEY: Operations wallet private key
 * - DEPLOYER_ADDRESS: Expected Deployer contract address
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);

  console.log("EVM QuipFactory Deployment");
  console.log("==========================");
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

  // Get WOTSPlus address from release
  const wotsAddress = getReleaseAddress("WOTSPlus.sol");
  console.log(`WOTSPlus library: ${wotsAddress}`);

  // Verify WOTSPlus is deployed
  const wotsCode = await hre.ethers.provider.getCode(wotsAddress);
  if (wotsCode === "0x") {
    throw new Error(
      "WOTSPlus library not deployed.\n" +
        "Run deployment with --tags WOTSPlus first."
    );
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

  // Load QuipFactory bytecode from release (includes constructor args)
  const factoryRelease = loadReleaseBytecode("QuipFactory.sol");
  const factoryBytecode = factoryRelease.creationBytecode;
  const expectedAddress = factoryRelease.address;

  console.log(`Using release bytecode for address: ${expectedAddress}`);
  console.log(`Bytecode size: ${(factoryBytecode.length - 2) / 2} bytes`);

  if (factoryRelease.constructorArgs) {
    console.log(`Constructor args from release:`);
    console.log(`  initialOwner: ${factoryRelease.constructorArgs.initialOwner}`);
    console.log(`  wotsLibrary: ${factoryRelease.constructorArgs.wotsLibrary}`);
  }

  // Check if already deployed
  const existingCode = await hre.ethers.provider.getCode(expectedAddress);
  if (existingCode !== "0x") {
    console.log(`\nQuipFactory already deployed at: ${expectedAddress}`);
    console.log("Skipping deployment.");
    await saveAddresses(chainId, network.name, deployerAddress, wotsAddress, expectedAddress);
    return;
  }

  // Get Deployer contract instance
  const deployer = await hre.ethers.getContractAt("Deployer", deployerAddress, signer);

  // Deploy QuipFactory via Deployer contract using stored salt
  console.log("\nDeploying QuipFactory via Deployer contract...");
  const tx = await deployer.deploy(factoryBytecode, factoryRelease.salt);
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

  const factoryAddress = parsedLog?.args.addr;

  if (factoryAddress !== expectedAddress) {
    console.warn(
      `WARNING: Deployed address ${factoryAddress} doesn't match expected ${expectedAddress}`
    );
  }

  // Save addresses
  await saveAddresses(chainId, network.name, deployerAddress, wotsAddress, factoryAddress);

  console.log("\n==========================");
  console.log("QuipFactory Deployment Complete!");
  console.log("==========================");
  console.log(`Deployer:    ${deployerAddress}`);
  console.log(`WOTSPlus:    ${wotsAddress}`);
  console.log(`QuipFactory: ${factoryAddress}`);
  console.log(`Gas used:    ${receipt.gasUsed}`);
  console.log(`Total cost:  ${hre.ethers.formatEther(receipt.gasUsed * receipt.gasPrice)} ETH`);
  console.log("\nNext steps:");
  console.log("1. Update src/addresses.ts with these addresses if needed");
  console.log("2. Run integration tests: npx hardhat test --network " + network.name);
};

async function saveAddresses(
  chainId: number,
  networkName: string,
  deployerAddress: string,
  wotsAddress: string,
  factoryAddress: string
): Promise<void> {
  const addressesFile = path.join(__dirname, `../../src/addresses-${networkName}.json`);
  const addresses = {
    chainId,
    network: networkName,
    Deployer: deployerAddress,
    WOTSPlus: wotsAddress,
    QuipFactory: factoryAddress,
  };

  fs.writeFileSync(addressesFile, JSON.stringify(addresses, null, 2));
  console.log(`\nAddresses saved to: ${addressesFile}`);
}

export default func;
func.tags = ["QuipFactory"];
func.dependencies = ["WOTSPlus"];
// Skip for MIDL networks (uses separate deploy scripts in deploy/midl_regtest/)
func.skip = async (hre) => {
  const network = await hre.ethers.provider.getNetwork();
  return Number(network.chainId) === MIDL_CHAIN_ID;
};
