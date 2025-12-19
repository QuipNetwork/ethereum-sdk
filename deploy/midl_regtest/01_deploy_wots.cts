// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { loadReleaseBytecode } = require("../../lib/deploy.cts");

// Type import for MidlHRE
import type { MidlHRE } from "../../lib/midl.cts";

/**
 * MIDL WOTSPlus Library Deployment
 *
 * This script deploys the WOTSPlus library via the Deployer contract using CREATE2.
 * Uses the stored release bytecode from deployments/bytecode/ to ensure
 * deterministic addresses matching the mainnet deployment.
 *
 * Prerequisites:
 * - Deployer contract must be deployed (run with --tags Deployer first)
 * - BTC_MNEMONIC wallet must have funds
 *
 * Usage:
 * npx hardhat deploy --network midl_regtest --tags WOTSPlus
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const midlHre = hre as MidlHRE;

  console.log("MIDL WOTSPlus Library Deployment");
  console.log("=================================");

  // Initialize the MIDL SDK
  console.log("Initializing MIDL connection...");
  await midlHre.midl.initialize();

  // Get addresses
  const { address: btcAddress, addressType } = midlHre.midl.getAccount();
  const evmAddress = midlHre.midl.getEVMAddress();
  console.log(`\nOperations Wallet:`);
  console.log(`  Bitcoin: ${btcAddress} (${addressType})`);
  console.log(`  EVM:     ${evmAddress}`);

  // Check for Deployer contract
  const deployerDeployment = await midlHre.midl.getDeployment("Deployer");
  if (!deployerDeployment) {
    throw new Error(
      "Deployer contract not found.\n" +
        "Run deployment with --tags Deployer first using midl_regtest_deployer network."
    );
  }
  console.log(`\nDeployer contract: ${deployerDeployment.address}`);

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

  // Check balance
  const balance = await hre.ethers.provider.getBalance(evmAddress);
  console.log(`\nWallet balance: ${hre.ethers.formatEther(balance)} ETH`);

  if (balance === 0n) {
    throw new Error(
      "Operations wallet has no balance.\n" +
        "Fund it with testnet BTC from: https://faucet.regtest.midl.xyz\n" +
        "Or run: npx hardhat run scripts/drainDeployer.ts --network midl_regtest"
    );
  }

  // Get signer and connect to Deployer contract
  const [signer] = await hre.ethers.getSigners();
  const deployer = await hre.ethers.getContractAt(
    "Deployer",
    deployerDeployment.address,
    signer
  );

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

  console.log("\n=================================");
  console.log("WOTSPlus Deployment Complete!");
  console.log("=================================");
  console.log(`WOTSPlus: ${wotsAddress}`);
  console.log(`Gas used: ${receipt.gasUsed}`);
  console.log("\nNext steps:");
  console.log("1. Deploy QuipFactory: npx hardhat deploy --network midl_regtest --tags QuipFactory");
};

export default func;
func.tags = ["WOTSPlus"];
func.dependencies = ["Deployer"];
// Only run on MIDL networks
func.skip = async (hre: HardhatRuntimeEnvironment) => {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  return chainId !== 777; // MIDL chain ID
};
