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

import hre from "hardhat";
import "dotenv/config";
import { EXPECTED_NONCE } from "./addNetwork";

async function main() {
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
    throw new Error(`DEPLOYER_PUBLIC_KEY incorrect, got ${deployerAddress} 
            expected ${process.env.DEPLOYER_PUBLIC_KEY}`);
  }

  // Get current nonce and balance
  const nonce = await hre.ethers.provider.getTransactionCount(deployerAddress);
  const balance = await hre.ethers.provider.getBalance(deployerAddress);
  const network = await hre.ethers.provider.getNetwork();

  console.log("\nCurrent network and wallet status:");
  console.log("----------------------------------");
  console.log(`Network: ${network.name} (chainId: ${network.chainId})`);
  console.log(`From Address: ${deployerAddress}`);
  console.log(`To Address: ${targetAddress}`);
  console.log(`Nonce: ${nonce}`);
  console.log(`Balance: ${hre.ethers.formatEther(balance)} ETH\n`);

  if (nonce <= EXPECTED_NONCE) {
    throw new Error(
      `Cannot drain: Current nonce (${nonce}) is not greater than EXPECTED_NONCE (${EXPECTED_NONCE})`
    );
  }

  if (balance === 0n) {
    console.log("No funds to drain");
    return;
  }

  // Estimate gas for the transfer with a 10% buffer on gas price
  const gasPrice = await hre.ethers.provider.getFeeData();
  if (!gasPrice.gasPrice) throw new Error("Failed to get gas price");

  const gasLimit = 21000n; // Standard ETH transfer
  // NOTE: use below for arbitrum
  //const gasLimit = 30000n;
  // NOTE: use below for mantle
  //const gasLimit = 200000000n;
  const gasCost = (gasPrice.gasPrice * gasLimit * 120n) / 100n; // Add 10% buffer

  // Calculate amount to send (total balance minus gas cost)
  const amountToSend = balance - gasCost;

  if (amountToSend <= 0n) {
    throw new Error("Balance too low to cover gas costs");
  }

  console.log("Drain Transaction Details:");
  console.log("-------------------------");
  console.log(`To: ${targetAddress}`);
  console.log(`Amount: ${hre.ethers.formatEther(amountToSend)} ETH`);
  console.log(
    `Gas Price: ${hre.ethers.formatUnits(gasPrice.gasPrice, "gwei")} Gwei`
  );
  console.log(
    `Estimated Gas Cost (with 20% buffer): ${hre.ethers.formatEther(
      gasCost
    )} ETH`
  );

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
    `Final gas cost: ${hre.ethers.formatEther(
      receipt?.gasUsed! * receipt?.gasPrice!
    )} ETH`
  );
}

if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

export { main as drainDeployer };
