// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import { getBalance } from "@midl/core";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { loadReleaseBytecode } = require("../../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getMidlEnvironment } = require("../../lib/midl.cts");

// Type import for MidlEnvironment
import type { MidlEnvironment } from "../../lib/midl.cts";

/**
 * MIDL WOTSPlus Library Deployment
 *
 * This script deploys the WOTSPlus library via the Deployer contract using CREATE2.
 * Uses the stored release bytecode from deployments/bytecode/ to ensure
 * deterministic addresses matching the mainnet deployment.
 *
 * Supports both PRIVATE_KEY (same address as Ethereum) and BTC_MNEMONIC.
 *
 * Prerequisites:
 * - Deployer contract must be deployed (run with --tags Deployer first)
 * - Operations wallet must have funds
 *
 * Usage:
 * npx hardhat deploy --network midl_regtest --tags WOTSPlus
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  console.log("MIDL WOTSPlus Library Deployment");
  console.log("=================================");

  // Get MIDL environment (uses private key if available, falls back to mnemonic)
  const midl: MidlEnvironment = getMidlEnvironment(hre, "midl_regtest");

  // Initialize the MIDL SDK with operations wallet (index 0)
  console.log("Initializing MIDL connection...");
  await midl.initialize(0);

  // Get addresses
  const account = midl.getAccount();
  const btcAddress = account.address;
  const addressType = account.addressType || "unknown";
  const evmAddress = midl.getEVMAddress();
  console.log(`\nOperations Wallet:`);
  console.log(`  Bitcoin: ${btcAddress} (${addressType})`);
  console.log(`  EVM:     ${evmAddress}`);

  // Check for Deployer contract
  const deployerDeployment = await midl.getDeployment("Deployer");
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

  // Query BTC balance from MIDL
  const config = midl.getConfig();
  if (!config) throw new Error("MIDL config not initialized");
  const btcBalanceSats = await getBalance(config, btcAddress);
  const btcBalance = btcBalanceSats / 100_000_000;
  console.log(`\nBTC Balance: ${btcBalance} BTC (${btcBalanceSats} sats)`);

  if (btcBalanceSats === 0) {
    throw new Error(
      `Operations wallet has no BTC balance.\n` +
        `Fund ${btcAddress} with testnet BTC from: https://faucet.regtest.midl.xyz`
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
