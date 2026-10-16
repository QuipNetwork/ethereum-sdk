// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Fund Deployer Wallet
 *
 * Transfers funds from the operations wallet to the deployer wallet.
 * Automatically detects network type (EVM or MIDL) and uses appropriate credentials.
 *
 * EVM Networks:
 *   - Uses PRIVATE_KEY for source wallet (operations)
 *   - Uses DEPLOYER_PRIVATE_KEY for destination wallet (deployer)
 *
 * MIDL Network:
 *   - Uses PRIVATE_KEY for source wallet (same as EVM)
 *   - Uses DEPLOYER_PRIVATE_KEY for destination wallet (same as EVM)
 *
 * Usage:
 *   npx hardhat run scripts/fundDeployer.cts --network <network>
 *
 * Environment:
 *   FUND_AMOUNT - Amount to transfer (e.g., "0.1" for 0.1 ETH/BTC). If not set, prompts for amount.
 */

import hre from "hardhat";
import "dotenv/config";
import { getBalance, transferBTC, waitForTransaction } from "@midl/core";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getNetworkInfo } = require("../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { getMidlEnvironment, midlGetOperationsAddresses, midlDeriveBtcAddress, hasMidlPlugin } = require("../lib/midl.cts");

// Type import for MidlEnvironment
import type { MidlEnvironment } from "../lib/midl.cts";

async function main() {
  const networkInfo = await getNetworkInfo(hre);

  console.log("\nFund Deployer Wallet");
  console.log("====================");
  console.log(`Network: ${networkInfo.name} (chainId: ${networkInfo.chainId})`);

  if (networkInfo.isMidl) {
    await fundMidl();
  } else {
    await fundEvm();
  }
}

/**
 * Fund deployer on EVM networks
 */
async function fundEvm() {
  // Validate environment
  if (!process.env.PRIVATE_KEY) {
    throw new Error("PRIVATE_KEY must be set in .env file");
  }
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    throw new Error("DEPLOYER_PRIVATE_KEY must be set in .env file");
  }

  // Create wallets
  const operations = new hre.ethers.Wallet(
    process.env.PRIVATE_KEY!,
    hre.ethers.provider
  );
  const deployer = new hre.ethers.Wallet(process.env.DEPLOYER_PRIVATE_KEY!);

  const operationsAddress = await operations.getAddress();
  const deployerAddress = await deployer.getAddress();

  // Get current balances
  const operationsBalance = await hre.ethers.provider.getBalance(operationsAddress);
  const deployerBalance = await hre.ethers.provider.getBalance(deployerAddress);

  console.log("\nOperations Wallet (source):");
  console.log(`  Address: ${operationsAddress}`);
  console.log(`  Balance: ${hre.ethers.formatEther(operationsBalance)} ETH`);

  console.log("\nDeployer Wallet (destination):");
  console.log(`  Address: ${deployerAddress}`);
  console.log(`  Balance: ${hre.ethers.formatEther(deployerBalance)} ETH`);

  // Get amount to fund
  const fundAmount = process.env.FUND_AMOUNT;
  if (!fundAmount) {
    throw new Error(
      "FUND_AMOUNT must be set in environment.\n" +
      "Example: FUND_AMOUNT=0.1 npx hardhat run scripts/fundDeployer.cts --network <network>"
    );
  }

  const amountToSend = hre.ethers.parseEther(fundAmount);

  // Estimate gas
  const gasPrice = await hre.ethers.provider.getFeeData();
  if (!gasPrice.gasPrice) throw new Error("Failed to get gas price");

  const gasLimit = 21000n; // Standard ETH transfer
  const gasCost = (gasPrice.gasPrice * gasLimit * 120n) / 100n; // Add 20% buffer

  const totalNeeded = amountToSend + gasCost;

  if (operationsBalance < totalNeeded) {
    throw new Error(
      `Insufficient balance. Need ${hre.ethers.formatEther(totalNeeded)} ETH ` +
      `(${fundAmount} + gas), but only have ${hre.ethers.formatEther(operationsBalance)} ETH`
    );
  }

  console.log("\nFund Transaction Details:");
  console.log("-------------------------");
  console.log(`To:        ${deployerAddress}`);
  console.log(`Amount:    ${fundAmount} ETH`);
  console.log(`Gas Price: ${hre.ethers.formatUnits(gasPrice.gasPrice, "gwei")} Gwei`);
  console.log(`Est. Gas:  ${hre.ethers.formatEther(gasCost)} ETH`);

  // Send the transaction
  const tx = await operations.sendTransaction({
    to: deployerAddress,
    value: amountToSend,
    gasLimit: gasLimit,
    gasPrice: gasPrice.gasPrice,
  });

  console.log("\nTransaction sent:", tx.hash);

  // Wait for confirmation
  const receipt = await tx.wait();
  console.log("\nTransaction confirmed!");
  console.log(`Gas used: ${receipt?.gasUsed.toString()} units`);
  console.log(
    `Final gas cost: ${hre.ethers.formatEther(receipt?.gasUsed! * receipt?.gasPrice!)} ETH`
  );

  // Show final balances
  const finalDeployerBalance = await hre.ethers.provider.getBalance(deployerAddress);
  console.log(`\nDeployer new balance: ${hre.ethers.formatEther(finalDeployerBalance)} ETH`);
}

/**
 * Fund deployer on MIDL network
 *
 * Uses hre.midl.transferBtc() to send BTC from operations to deployer.
 * Since MIDL links BTC and EVM addresses (same key), this funds both layers.
 */
async function fundMidl() {
  // Validate environment
  if (!process.env.PRIVATE_KEY) {
    throw new Error("PRIVATE_KEY must be set in .env file");
  }
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    throw new Error("DEPLOYER_PRIVATE_KEY must be set in .env file");
  }

  // Check for MIDL plugin
  if (!hasMidlPlugin(hre)) {
    throw new Error(
      "MIDL plugin not available. Make sure @midl/hardhat-deploy is installed."
    );
  }

  // Get MIDL environment and initialize with operations wallet (index 0)
  const midl: MidlEnvironment = getMidlEnvironment(hre);
  console.log("\nInitializing MIDL connection with operations wallet...");
  await midl.initialize(0);

  // Get operations wallet addresses
  const operationsAccount = midl.getAccount();
  const operationsBtcAddress = operationsAccount.address;
  const addressType = operationsAccount.addressType || "p2wpkh";
  const operationsEvmAddress = midl.getEVMAddress();

  console.log("\nOperations Wallet (source):");
  console.log(`  Bitcoin: ${operationsBtcAddress} (${addressType})`);
  console.log(`  EVM:     ${operationsEvmAddress}`);

  // Verify it matches our expected address (compare lowercase for case-insensitive match)
  const expectedAddresses = midlGetOperationsAddresses("regtest");
  if (expectedAddresses && operationsEvmAddress.toLowerCase() !== expectedAddresses.evm.toLowerCase()) {
    throw new Error(
      `Operations EVM address mismatch!\n` +
      `  Connector: ${operationsEvmAddress}\n` +
      `  Expected:  ${expectedAddresses.evm}`
    );
  }

  // Get deployer BTC address (derived from DEPLOYER_PRIVATE_KEY)
  const deployerBtcAddress = midlDeriveBtcAddress(process.env.DEPLOYER_PRIVATE_KEY, "regtest");

  console.log("\nDeployer Wallet (destination):");
  console.log(`  Bitcoin: ${deployerBtcAddress}`);

  // Get MIDL config for @midl/core functions
  const config = midl.getConfig();
  if (!config) throw new Error("MIDL config not initialized");

  // Get current balance
  const btcBalanceSats = await getBalance(config, operationsBtcAddress);
  const btcBalance = btcBalanceSats / 100_000_000;

  console.log("\nOperations Status:");
  console.log(`  Balance: ${btcBalance} BTC (${btcBalanceSats} sats)`);

  // Get amount to fund
  const fundAmount = process.env.FUND_AMOUNT;
  if (!fundAmount) {
    throw new Error(
      "FUND_AMOUNT must be set in environment.\n" +
      "Example: FUND_AMOUNT=0.001 npx hardhat run scripts/fundDeployer.cts --network midl_regtest"
    );
  }

  const amountBtc = parseFloat(fundAmount);
  const amountSats = Math.floor(amountBtc * 100_000_000);

  if (btcBalanceSats < amountSats) {
    throw new Error(
      `Insufficient balance. Need ${amountBtc} BTC (${amountSats} sats), ` +
      `but only have ${btcBalance} BTC (${btcBalanceSats} sats)`
    );
  }

  console.log("\nFund Transaction Details:");
  console.log("-------------------------");
  console.log(`To:     ${deployerBtcAddress}`);
  console.log(`Amount: ${amountBtc} BTC (${amountSats} sats)`);

  // Transfer BTC from operations to deployer
  console.log("\nSending BTC transfer...");
  const transferResult = await transferBTC(config, {
    transfers: [{ receiver: deployerBtcAddress, amount: amountSats }],
    publish: true,
  });

  console.log(`\nTransaction sent: ${transferResult.tx.id}`);

  // Wait for confirmation
  console.log("Waiting for confirmation...");
  await waitForTransaction(config, transferResult.tx.id, 1);
  console.log("Transfer complete!");

  // Verify final balance
  const finalBalanceSats = await getBalance(config, deployerBtcAddress);
  const finalBalance = finalBalanceSats / 100_000_000;
  console.log(`Deployer new balance: ${finalBalance} BTC (${finalBalanceSats} sats)`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

export { main as fundDeployer };
