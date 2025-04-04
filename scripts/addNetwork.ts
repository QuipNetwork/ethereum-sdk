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

// addNetwork.ts is called exactly once per network. 
// It deploys the Deployer contract and checks it against the .env
// file DEPLOYER_ADDRESS.
//
// To use, you must set DEPLOYER_PRIVATE_KEY and DEPLOYER_PUBLIC_KEY
// in .env. These must be the keys and address provided by Rick for
// everything to work (Colton also has a copy).
// 
// If you are not Rick, you probably should not be running this script.
// Call Rick. Get permission. Don't be an idiot.
//
// Examples:
//
//    npx hardhat run scripts/addNetwork.ts --network sepolia
//    npx hardhat run scripts/addNetwork.ts --network sepolia_base
//    npx hardhat run scripts/addNetwork.ts --network sepolia_optimism
import hre from "hardhat";
import "dotenv/config";

async function checkWalletNonce(address: string) {
    const nonce = await hre.ethers.provider.getTransactionCount(address);
    const balance = await hre.ethers.provider.getBalance(address);
    const balanceInEth = parseFloat(balance.toString()) / 1e18;
    const network = await hre.ethers.provider.getNetwork();
    
    console.log("\nCurrent network and wallet status:");
    console.log("----------------------------------");
    console.log(`Network: ${network.name} (chainId: ${network.chainId})`);
    console.log(`Address: ${address}`);
    console.log(`Nonce: ${nonce}`);
    console.log(`Balance: ${balanceInEth.toFixed(4)} ETH\n`);

    return { curNonce: nonce, curBalance: balanceInEth };
}

// CRITICAL: THIS NONCE MUST BE THE SAME ON ALL NETWORKS
// TALK TO RICK. DO NOT MODIFY.
// IF the Nonce is < EXPECTED_NONCE, we simply deploy
// the contract multiple times.
const EXPECTED_NONCE = 1;
const MIN_BALANCE = 0.04;

async function main() {
    if (!process.env.DEPLOYER_PRIVATE_KEY) {
        throw new Error("DEPLOYER_PRIVATE_KEY must be set in .env file");
    }
    if (!process.env.DEPLOYER_PUBLIC_KEY) {
        throw new Error("DEPLOYER_PUBLIC_KEY must be set in .env file");
    }
    if (!process.env.DEPLOYER_ADDRESS) {
        throw new Error("DEPLOYER_ADDRESS must be set in .env file");
    }

    // Check if Deployer contract already exists at the expected address
    const code = await hre.ethers.provider.getCode(process.env.DEPLOYER_ADDRESS);
    if (code !== "0x") {
        throw new Error(`Deployer contract already exists at ${process.env.DEPLOYER_ADDRESS} on this network`);
    }

    // Create wallet from private key
    const deployer = new hre.ethers.Wallet(
        process.env.DEPLOYER_PRIVATE_KEY!,
        hre.ethers.provider
    );

    const deployerAddress = await deployer.getAddress();

    if (process.env.DEPLOYER_PUBLIC_KEY !== deployerAddress) {
        throw new Error(`DEPLOYER_PUBLIC_KEY incorrect, got ${deployerAddress} 
            expected ${process.env.DEPLOYER_PUBLIC_KEY}`);
    }

    const { curNonce, curBalance } = await checkWalletNonce(deployerAddress);

    if (curNonce > EXPECTED_NONCE) {
        throw new Error(`CRITICAL ERROR: Nonce is greater than expected value of ${EXPECTED_NONCE}.
            Tell Rick NOW, as you have just forced a complete platform wide upgrade and invalidated
            all existing wallet addresses.`);
    }

    if (curBalance < MIN_BALANCE) {
        throw new Error(`balance too low (${curBalance} ETH). Needs at least ${MIN_BALANCE} ETH.}`);
    }

    // NOTE: It is critical that you run this with a wallet with the same nonce value
    // on every network you are deploying. Talk to Rick about how to do this.
    // We set up a wallet with the same nonce on all networks,
    // deploy the Deployer contract, get that contract address, and use 
    // that as a global constant moving forward.
    for (let i = curNonce; i <= EXPECTED_NONCE; i++) {
        console.log(`Deploying Deployer with nonce ${i}...`);
        const Deployer = await hre.ethers.getContractFactory("Deployer", deployer);
        const deployerContract = await Deployer.deploy();
        const deployReceipt = await deployerContract.waitForDeployment();
        
        // Get deployment transaction
        const deployTx = deployReceipt.deploymentTransaction();
        if (!deployTx) throw new Error("Deployment transaction not found");
        
        const receipt = await deployTx.wait();
        if (!receipt) throw new Error("Failed to get transaction receipt");

        const deployGasFee = receipt.gasUsed * receipt.gasPrice;
        const deployerAddress = await deployerContract.getAddress();

        if (i == EXPECTED_NONCE && deployerAddress !== process.env.DEPLOYER_ADDRESS) {
            console.error(`Deployer address mismatch. Expected ${process.env.DEPLOYER_ADDRESS} but got ${deployerAddress}`);
        }

        console.log("\nDeployment Details:");
        console.log("-------------------");
        console.log(`Deployer deployed to: ${deployerAddress}`);
        console.log(`Gas used: ${receipt.gasUsed} units`);
        console.log(`Gas price: ${receipt.gasPrice} wei`);
        console.log(`Total gas cost: ${hre.ethers.formatEther(deployGasFee)} ETH`);
    }
}

if (require.main === module) {
    main()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}

export { main as addNetwork };