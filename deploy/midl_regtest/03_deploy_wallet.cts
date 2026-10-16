// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import { getBalance } from "@midl/core";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { loadReleaseBytecode, getReleaseAddress } = require("../../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getMidlEnvironment } = require("../../lib/midl.cts");

// Type import for MidlEnvironment
import type { MidlEnvironment } from "../../lib/midl.cts";

/**
 * MIDL QuipWallet Implementation Deployment
 *
 * Mirrors `script/DeployImplementation.s.sol`: deploys the QuipWallet
 * implementation via the Deployer contract using CREATE3. Uses the stored
 * release bytecode (factory address baked in as constructor arg + WOTSPlus
 * library linked) so the implementation lands at the same address as on
 * EVM chains.
 *
 * Vetting the implementation on the factory is a separate step
 * (`05_vet_wallet.cts`), matching the Forge two-script split
 * (DeployImplementation + VetImplementation).
 *
 * Prerequisites:
 * - Deployer contract must be deployed (--tags Deployer first)
 * - WOTSPlus library must be deployed (--tags WOTSPlus first)
 * - QuipFactory must be deployed (--tags QuipFactory first)
 * - Operations wallet must have funds
 *
 * Usage:
 *   npx hardhat deploy --network midl_regtest --tags QuipWallet
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  console.log("MIDL QuipWallet Implementation Deployment");
  console.log("==========================================");

  // Get MIDL environment (uses private key if available, falls back to mnemonic)
  const midl: MidlEnvironment = getMidlEnvironment(hre, "midl_regtest");

  console.log("Initializing MIDL connection...");
  await midl.initialize(0);

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

  // Load wallet implementation linked creation bytecode from release. The
  // release snapshot is ctor-args-free (matches QuipFactory + paymaster
  // proxy); we abi-encode `(factory_)` and append here. The factory address
  // is canonical (CREATE3-deterministic) so it's the same on every chain.
  const walletRelease = loadReleaseBytecode("QuipWallet.sol");
  const expectedAddress = walletRelease.address;
  const factoryAddress: string = getReleaseAddress("QuipFactory.sol");

  const ctorArgs = hre.ethers.AbiCoder.defaultAbiCoder().encode(
    ["address"],
    [factoryAddress]
  );
  const walletBytecode = walletRelease.creationBytecode + ctorArgs.slice(2);

  console.log(`\nQuipFactory (ctor arg): ${factoryAddress}`);

  console.log(`Using release bytecode for address: ${expectedAddress}`);
  console.log(`Bytecode size: ${(walletBytecode.length - 2) / 2} bytes`);

  // Idempotency check.
  const existingCode = await hre.ethers.provider.getCode(expectedAddress);
  if (existingCode !== "0x") {
    console.log(`\nQuipWallet implementation already deployed at: ${expectedAddress}`);
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

  console.log("\nDeploying QuipWallet implementation via Deployer contract...");
  const tx = await deployer.deploy(walletBytecode, walletRelease.salt);
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

  const implAddress = parsedLog?.args.addr;

  if (implAddress !== expectedAddress) {
    console.warn(
      `WARNING: Deployed address ${implAddress} doesn't match expected ${expectedAddress}`
    );
  }

  console.log("\n==========================================");
  console.log("QuipWallet Implementation Deployment Complete!");
  console.log("==========================================");
  console.log(`QuipWallet (impl): ${implAddress}`);
  console.log(`Gas used:          ${receipt.gasUsed}`);
  console.log("\nNext step:");
  console.log("  npx hardhat deploy --network midl_regtest --tags VetWallet");
  console.log("  (must be run by the factory owner)");
};

export default func;
func.tags = ["QuipWallet"];
func.dependencies = ["QuipFactory"];
// Only run on MIDL networks
func.skip = async (hre: HardhatRuntimeEnvironment) => {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  return chainId !== 777; // MIDL chain ID
};
