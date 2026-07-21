// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import fs from "fs";
import path from "path";
import { getBalance } from "@midl/core";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { loadReleaseBytecode, getReleaseAddress } = require("../../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getMidlEnvironment } = require("../../lib/midl.cts");

// Type import for MidlEnvironment
import type { MidlEnvironment } from "../../lib/midl.cts";

/**
 * MIDL QuipFactory Deployment
 *
 * This script deploys the QuipFactory contract via the Deployer contract using CREATE2.
 * Uses the stored release bytecode from deployments/bytecode/ to ensure
 * deterministic addresses matching the mainnet deployment.
 *
 * Note: The release bytecode includes constructor args (initialOwner, wotsLibrary)
 * baked in from the mainnet deployment. This ensures the same address across all chains.
 *
 * Supports both PRIVATE_KEY (same address as Ethereum) and BTC_MNEMONIC.
 *
 * Prerequisites:
 * - Deployer contract must be deployed (run with --tags Deployer first)
 * - WOTSPlus library must be deployed (run with --tags WOTSPlus first)
 * - Operations wallet must have funds
 *
 * Usage:
 * npx hardhat deploy --network midl_regtest --tags QuipFactory
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  console.log("MIDL QuipFactory Deployment");
  console.log("===========================");

  // Validate FACTORY_OWNER + MAX_FEE early — these are baked into the
  // creation bytecode at deploy time. Setting either to a placeholder would
  // ship a broken factory (vetImplementation reverts under onlyOwner if
  // initialOwner = 0x0). Mirrors the env-var contract of 01_DeployFactory.s.sol.
  const factoryOwner = process.env.FACTORY_OWNER;
  if (!factoryOwner) {
    throw new Error("FACTORY_OWNER must be set in env / .env file");
  }
  if (!hre.ethers.isAddress(factoryOwner)) {
    throw new Error(`FACTORY_OWNER is not a valid address: ${factoryOwner}`);
  }
  if (factoryOwner === hre.ethers.ZeroAddress) {
    throw new Error("FACTORY_OWNER must be non-zero");
  }

  const maxFeeRaw = process.env.MAX_FEE;
  if (!maxFeeRaw) {
    throw new Error(
      "MAX_FEE must be set in env / .env file (wei, e.g. 100000000000000000 for 0.1 ETH)"
    );
  }
  let maxFee: bigint;
  try {
    maxFee = BigInt(maxFeeRaw);
  } catch {
    throw new Error(`MAX_FEE must be an integer (wei). Got: ${maxFeeRaw}`);
  }
  if (maxFee === 0n) {
    throw new Error("MAX_FEE must be non-zero");
  }

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
  console.log(`\nFactory owner: ${factoryOwner}`);
  console.log(`Max fee:       ${maxFee} wei`);

  // Check for Deployer contract
  const deployerDeployment = await midl.getDeployment("Deployer");
  if (!deployerDeployment) {
    throw new Error(
      "Deployer contract not found.\n" +
        "Run deployment with --tags Deployer first using midl_regtest_deployer network."
    );
  }
  console.log(`\nDeployer contract: ${deployerDeployment.address}`);

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

  // Load QuipFactory linked creation bytecode from release. The release
  // snapshot stops at "linked creation code, no ctor args" so we encode
  // and append `(initialOwner, maxFee_)` here at deploy time — same
  // contract as 01_DeployFactory.s.sol and 04_deploy_paymaster.cts.
  const factoryRelease = loadReleaseBytecode("QuipFactory.sol");
  const expectedAddress = factoryRelease.address;
  const ctorArgs = hre.ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "uint256"],
    [factoryOwner, maxFee]
  );
  const factoryBytecode = factoryRelease.creationBytecode + ctorArgs.slice(2);

  console.log(`Using release bytecode for address: ${expectedAddress}`);
  console.log(`Bytecode size: ${(factoryBytecode.length - 2) / 2} bytes`);

  // Check if already deployed
  const existingCode = await hre.ethers.provider.getCode(expectedAddress);
  if (existingCode !== "0x") {
    console.log(`\nQuipFactory already deployed at: ${expectedAddress}`);
    console.log("Skipping deployment.");
    await saveMidlAddresses(deployerDeployment.address, wotsAddress, expectedAddress);
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

  // Save MIDL addresses
  await saveMidlAddresses(deployerDeployment.address, wotsAddress, factoryAddress);

  console.log("\n===========================");
  console.log("QuipFactory Deployment Complete!");
  console.log("===========================");
  console.log(`Deployer:    ${deployerDeployment.address}`);
  console.log(`WOTSPlus:    ${wotsAddress}`);
  console.log(`QuipFactory: ${factoryAddress}`);
  console.log(`Gas used:    ${receipt.gasUsed}`);
  console.log("\nNext steps:");
  console.log("1. Update src/addresses.ts NETWORK_ADDRESSES[777] with these addresses");
  console.log("2. Verify on https://blockscout.regtest.midl.xyz");
  console.log("3. Run integration tests: npx hardhat test test/midl-integration.ts --network midl_regtest");
};

async function saveMidlAddresses(
  deployerAddress: string,
  wotsAddress: string,
  factoryAddress: string
): Promise<void> {
  const addressesFile = path.join(__dirname, "../../src/addresses-midl.json");
  const addresses = {
    chainId: 777,
    network: "midl_regtest",
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
// Only run on MIDL networks
func.skip = async (hre: HardhatRuntimeEnvironment) => {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  return chainId !== 777; // MIDL chain ID
};
