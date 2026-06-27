// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import fs from "fs";
import path from "path";
import { getBalance } from "@midl/core";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getReleaseAddress } = require("../../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getMidlEnvironment } = require("../../lib/midl.cts");

// Type import for MidlEnvironment
import type { MidlEnvironment } from "../../lib/midl.cts";

/**
 * MIDL QuipWallet Implementation Vetting
 *
 * Mirrors `script/VetImplementation.s.sol`: calls
 * `QuipFactory.vetImplementation(impl)` on the QuipFactory to register the
 * deployed wallet implementation as vetted. The caller must be the factory
 * owner.
 *
 * Reads:
 *   - QuipFactory address from `src/addresses-midl.json` (written by
 *     02_deploy_factory.cts).
 *   - QuipWallet impl address from the release snapshot.
 *
 * Prerequisites:
 * - QuipFactory must be deployed (--tags QuipFactory)
 * - QuipWallet implementation must be deployed (--tags QuipWallet)
 * - Operations wallet must be the factory owner
 * - Operations wallet must have funds
 *
 * Usage:
 *   npx hardhat deploy --network midl_regtest --tags VetWallet
 */

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  console.log("MIDL QuipWallet Vetting");
  console.log("========================");

  // Get MIDL environment
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

  // Load MIDL addresses written by 02_deploy_factory.cts.
  const addressesFile = path.join(__dirname, "../../src/addresses-midl.json");
  if (!fs.existsSync(addressesFile)) {
    throw new Error(
      `MIDL addresses file not found: ${addressesFile}\n` +
        `Run --tags QuipFactory first.`
    );
  }
  const midlAddresses = JSON.parse(fs.readFileSync(addressesFile, "utf-8"));
  const factoryAddress: string = midlAddresses.QuipFactory;
  if (!factoryAddress) {
    throw new Error(
      `QuipFactory address missing from ${addressesFile}. Run --tags QuipFactory first.`
    );
  }

  // Wallet impl from the release snapshot. The release file records the
  // canonical CREATE3 address — same on MIDL as on EVM because CREATE3
  // depends only on (Deployer, salt).
  const implAddress: string = getReleaseAddress("QuipWallet.sol");

  console.log(`\nFactory:        ${factoryAddress}`);
  console.log(`Implementation: ${implAddress}`);

  // Verify both are actually deployed
  const factoryCode = await hre.ethers.provider.getCode(factoryAddress);
  if (factoryCode === "0x") {
    throw new Error(`Factory not deployed at ${factoryAddress}`);
  }
  const implCode = await hre.ethers.provider.getCode(implAddress);
  if (implCode === "0x") {
    throw new Error(
      `Implementation not deployed at ${implAddress}. Run --tags QuipWallet first.`
    );
  }

  // Connect to the factory and confirm caller is owner before broadcasting.
  // Foundry's VetImplementation.s.sol relies on `onlyOwner` reverting the
  // tx if the caller isn't the owner; we surface that earlier here to avoid
  // burning gas on a guaranteed-revert MIDL tx.
  const factoryArtifactPath = path.join(
    __dirname,
    "../../out/QuipFactory.sol/QuipFactory.json"
  );
  if (!fs.existsSync(factoryArtifactPath)) {
    throw new Error(
      `QuipFactory Foundry artifact not found: ${factoryArtifactPath}\nRun \`forge build\` first.`
    );
  }
  const factoryArtifact = JSON.parse(
    fs.readFileSync(factoryArtifactPath, "utf-8")
  );

  const [signer] = await hre.ethers.getSigners();
  const factory = new hre.ethers.Contract(
    factoryAddress,
    factoryArtifact.abi,
    signer
  );

  const currentOwner: string = await factory.owner();
  console.log(`Factory owner:  ${currentOwner}`);
  if (currentOwner.toLowerCase() !== evmAddress.toLowerCase()) {
    throw new Error(
      `Caller (${evmAddress}) is not the factory owner (${currentOwner}).\n` +
        `vetImplementation reverts under onlyOwner — only the factory owner can run this script.`
    );
  }

  // Check BTC balance before broadcasting.
  const config = midl.getConfig();
  if (!config) throw new Error("MIDL config not initialized");
  const btcBalanceSats = await getBalance(config, btcAddress);
  const btcBalance = btcBalanceSats / 100_000_000;
  console.log(`BTC Balance:    ${btcBalance} BTC (${btcBalanceSats} sats)`);

  if (btcBalanceSats === 0) {
    throw new Error(
      `Operations wallet has no BTC balance.\n` +
        `Fund ${btcAddress} with testnet BTC from: https://faucet.regtest.midl.xyz`
    );
  }

  // Log impl codehash so the operator can sanity-check that the on-chain
  // bytecode matches the release snapshot before broadcasting.
  const implCodehash = hre.ethers.keccak256(implCode);
  console.log(`Impl codehash:  ${implCodehash}`);

  console.log("\nCalling factory.vetImplementation(impl)...");
  const tx = await factory.vetImplementation(implAddress);
  console.log(`Transaction submitted: ${tx.hash}`);
  console.log("Waiting for confirmation...");

  const receipt = await tx.wait();
  if (!receipt) {
    throw new Error("Vet transaction failed - no receipt");
  }

  const vettedCount: bigint = await factory.getVettedCodeCount();
  const latest: string = await factory.latestWalletImpl();

  console.log("\n========================");
  console.log("QuipWallet Vetting Complete!");
  console.log("========================");
  console.log(`Vetted code count:    ${vettedCount}`);
  console.log(`Latest wallet impl:   ${latest}`);
  console.log(`Gas used:             ${receipt.gasUsed}`);
};

export default func;
func.tags = ["VetWallet"];
func.dependencies = ["QuipWallet"];
// Only run on MIDL networks
func.skip = async (hre: HardhatRuntimeEnvironment) => {
  const network = await hre.ethers.provider.getNetwork();
  const chainId = Number(network.chainId);
  return chainId !== 777; // MIDL chain ID
};
