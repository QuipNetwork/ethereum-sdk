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
 * Drain Deployer Wallet
 *
 * Transfers remaining funds from the deployer wallet to the operations wallet.
 * Automatically detects network type (EVM or MIDL) and uses appropriate credentials.
 *
 * EVM Networks:
 *   - Uses DEPLOYER_PRIVATE_KEY for source wallet
 *   - Uses PRIVATE_KEY for destination wallet
 *
 * MIDL Network:
 *   - Uses DEPLOYER_BTC_MNEMONIC for source wallet (derived EVM address)
 *   - Uses BTC_MNEMONIC for destination wallet (derived EVM address)
 *
 * Usage:
 *   npx hardhat run scripts/drainDeployer.cts --network <network>
 */

import hre from "hardhat";
import "dotenv/config";

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { EXPECTED_DEPLOYER_NONCE, getNetworkInfo, drainWallet, printDrainSummary } = require("../lib/deploy.cts");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { midlGetOperationsAddress, midlInitialize, midlPrintAddresses, hasMidlPlugin } = require("../lib/midl.cts");

async function main() {
  const networkInfo = await getNetworkInfo(hre);

  console.log("\nDrain Deployer Wallet");
  console.log("=====================");
  console.log(`Network: ${networkInfo.name} (chainId: ${networkInfo.chainId})`);

  if (networkInfo.isMidl) {
    await drainMidl();
  } else {
    await drainEvm();
  }
}

/**
 * Drain deployer on EVM networks
 */
async function drainEvm() {
  // Validate environment
  if (!process.env.DEPLOYER_PRIVATE_KEY) {
    throw new Error("DEPLOYER_PRIVATE_KEY must be set in .env file");
  }
  if (!process.env.DEPLOYER_PUBLIC_KEY) {
    throw new Error("DEPLOYER_PUBLIC_KEY must be set in .env file");
  }
  if (!process.env.PRIVATE_KEY) {
    throw new Error("PRIVATE_KEY must be set in .env file");
  }

  // Create wallet from private key
  const deployer = new hre.ethers.Wallet(
    process.env.DEPLOYER_PRIVATE_KEY!,
    hre.ethers.provider
  );

  // Create target wallet from PRIVATE_KEY
  const targetWallet = new hre.ethers.Wallet(process.env.PRIVATE_KEY!);
  const targetAddress = await targetWallet.getAddress();

  const deployerAddress = await deployer.getAddress();
  if (process.env.DEPLOYER_PUBLIC_KEY !== deployerAddress) {
    throw new Error(
      `DEPLOYER_PUBLIC_KEY incorrect, got ${deployerAddress} expected ${process.env.DEPLOYER_PUBLIC_KEY}`
    );
  }

  // Get current nonce and balance
  const nonce = await hre.ethers.provider.getTransactionCount(deployerAddress);
  const balance = await hre.ethers.provider.getBalance(deployerAddress);

  console.log("\nDeployer Wallet:");
  console.log(`  Address: ${deployerAddress}`);
  console.log(`  Nonce:   ${nonce}`);
  console.log(`  Balance: ${hre.ethers.formatEther(balance)} ETH`);

  console.log("\nTarget Wallet:");
  console.log(`  Address: ${targetAddress}`);

  if (nonce <= EXPECTED_DEPLOYER_NONCE) {
    throw new Error(
      `Cannot drain: Current nonce (${nonce}) is not greater than EXPECTED_DEPLOYER_NONCE (${EXPECTED_DEPLOYER_NONCE})`
    );
  }

  if (balance === 0n) {
    console.log("\nNo funds to drain");
    return;
  }

  // Estimate gas for the transfer with a 10% buffer on gas price
  const gasPrice = await hre.ethers.provider.getFeeData();
  if (!gasPrice.gasPrice) throw new Error("Failed to get gas price");

  const gasLimit = 21000n; // Standard ETH transfer
  const gasCost = (gasPrice.gasPrice * gasLimit * 120n) / 100n; // Add 20% buffer

  // Calculate amount to send (total balance minus gas cost)
  const amountToSend = balance - gasCost;

  if (amountToSend <= 0n) {
    throw new Error("Balance too low to cover gas costs");
  }

  console.log("\nDrain Transaction Details:");
  console.log("-------------------------");
  console.log(`To:       ${targetAddress}`);
  console.log(`Amount:   ${hre.ethers.formatEther(amountToSend)} ETH`);
  console.log(`Gas Price: ${hre.ethers.formatUnits(gasPrice.gasPrice, "gwei")} Gwei`);
  console.log(`Est. Gas: ${hre.ethers.formatEther(gasCost)} ETH`);

  // Send the transaction
  const tx = await deployer.sendTransaction({
    to: targetAddress,
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
}

/**
 * Drain deployer on MIDL network
 */
async function drainMidl() {
  // Validate environment
  if (!process.env.DEPLOYER_BTC_MNEMONIC) {
    throw new Error("DEPLOYER_BTC_MNEMONIC must be set in .env file");
  }
  if (!process.env.BTC_MNEMONIC) {
    throw new Error("BTC_MNEMONIC must be set in .env file");
  }

  // Check for MIDL plugin
  if (!hasMidlPlugin(hre)) {
    throw new Error(
      "MIDL plugin not available. Make sure @midl/hardhat-deploy is installed."
    );
  }

  // Initialize MIDL and get deployer addresses
  console.log("\nInitializing MIDL connection...");
  const { btcAddress, btcAddressType, evmAddress: deployerEvmAddress } = await midlInitialize(hre);
  midlPrintAddresses("Deployer Wallet", btcAddress, btcAddressType, deployerEvmAddress);

  // Get operations address from BTC_MNEMONIC
  const targetAddress = midlGetOperationsAddress();
  if (!targetAddress) {
    throw new Error("Failed to derive operations address from BTC_MNEMONIC");
  }

  console.log("\nOperations Wallet:");
  console.log(`  EVM: ${targetAddress}`);

  // Get current state
  const [nonce, balance] = await Promise.all([
    hre.ethers.provider.getTransactionCount(deployerEvmAddress),
    hre.ethers.provider.getBalance(deployerEvmAddress),
  ]);

  console.log("\nDeployer Status:");
  console.log(`  Nonce:   ${nonce}`);
  console.log(`  Balance: ${hre.ethers.formatEther(balance)} ETH`);

  // Perform the drain
  const result = await drainWallet(hre, deployerEvmAddress, targetAddress, {
    minNonce: EXPECTED_DEPLOYER_NONCE,
    skipIfEmpty: false,
  });

  printDrainSummary(hre, result, deployerEvmAddress, targetAddress);

  if (!result.success) {
    throw new Error(result.error);
  }

  // Verify final balance
  const finalBalance = await hre.ethers.provider.getBalance(deployerEvmAddress);
  console.log(`\nDeployer remaining balance: ${hre.ethers.formatEther(finalBalance)} ETH`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

export { main as drainDeployer };
