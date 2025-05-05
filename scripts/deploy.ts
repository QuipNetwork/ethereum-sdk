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
import { addNetwork } from "./addNetwork";
import fs from "fs";
import path from "path";

const SALT = "QUIP";
const ADDRESSES_FILE = path.join(__dirname, "../src/addresses.json");
const TMP_ADDRESSES_FILE = path.join(__dirname, "../src/addresses.tmp.json");

async function computeAddress(
  bytecode: string,
  salt: string,
  deployerAddress: string
): Promise<string> {
  const creationCode = bytecode;
  const hash = hre.ethers.keccak256(
    hre.ethers.solidityPacked(
      ["bytes1", "address", "bytes32", "bytes32"],
      [
        "0xff",
        deployerAddress,
        hre.ethers.id(salt),
        hre.ethers.keccak256(creationCode),
      ]
    )
  );
  return hre.ethers.getAddress(`0x${hash.slice(-40)}`);
}

async function isContractDeployed(address: string): Promise<boolean> {
  const code = await hre.ethers.provider.getCode(address);
  return code !== "0x";
}

async function loadDeployer(deployerAddress: string) {
  const network = await hre.ethers.provider.getNetwork();
  const isHardhat = network.name === "hardhat";

  // First verify the deployer exists
  const isDeployed = await isContractDeployed(deployerAddress);

  if (!isDeployed) {
    if (!isHardhat) {
      throw new Error(
        `Deployer contract not found at ${deployerAddress} on current network`
      );
    }

    // On hardhat network, run addNetwork to deploy the Deployer contract
    await addNetwork();
  }

  // Get the contract instance
  const deployer = await hre.ethers.getContractAt("Deployer", deployerAddress);
  console.log(`Found Deployer contract at: ${deployerAddress}`);
  return deployer;
}

async function main() {
  const network = await hre.ethers.provider.getNetwork();
  const deployerAddress = process.env.DEPLOYER_ADDRESS!;

  // For Mantle, use specific deployment options with lower gas limits
  const deployOptions =
    network.name === "mantle"
      ? {
          gasLimit: 8000000000n, // Try a lower value than the max
          gasPrice: await hre.ethers.provider
            .getFeeData()
            .then((fd) => fd.gasPrice),
        }
      : {};

  if (network.name === "mantle") {
    console.log(
      "Configuring for Mantle network with gasLimit:",
      deployOptions.gasLimit
    );
  }

  // Get initial owner from environment variable or fall back to signer
  const initialOwnerArg = process.env.INITIAL_OWNER;

  if (deployerAddress === undefined || deployerAddress.length !== 42) {
    throw new Error("DEPLOYER_ADDRESS not set or wrong length in .env");
  }

  // Validate initial owner address if provided
  if (initialOwnerArg && !hre.ethers.isAddress(initialOwnerArg)) {
    throw new Error("Invalid INITIAL_OWNER address provided");
  }

  // Load the deployer contract
  const deployer = await loadDeployer(deployerAddress);

  // Get the bytecode for WOTSPlus
  const WOTSPlus = await hre.ethers.getContractFactory(
    "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus"
  );
  const wotsBytecode = WOTSPlus.bytecode;

  // Precompute WOTSPlus address
  const wotsExpectedAddress = await computeAddress(
    wotsBytecode,
    SALT,
    deployerAddress
  );
  const wotsAlreadyDeployed = await isContractDeployed(wotsExpectedAddress);

  let wotsAddress: string;
  if (wotsAlreadyDeployed) {
    console.log(`WOTSPlus already deployed at: ${wotsExpectedAddress}`);
    wotsAddress = wotsExpectedAddress;
  } else {
    console.log("Deploying WOTSPlus...");
    const wotsTx = await deployer.deploy(
      wotsBytecode,
      hre.ethers.id(SALT),
      deployOptions
    );
    const wotsReceipt = await wotsTx.wait();
    const wotsDeployEvent = wotsReceipt?.logs.find(
      (log) =>
        log.topics[0] === deployer.interface.getEvent("Deploy")?.topicHash
    );
    wotsAddress = deployer.interface.parseLog({
      topics: wotsDeployEvent!.topics,
      data: wotsDeployEvent!.data,
    })!.args.addr;
    console.log(`WOTSPlus deployed to: ${wotsAddress}`);
  }

  // Get the bytecode for QuipFactory
  const QuipFactory = await hre.ethers.getContractFactory("QuipFactory", {
    libraries: {
      "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus":
        wotsAddress,
    },
  });
  const factoryBytecode = QuipFactory.bytecode;

  const [signer] = await hre.ethers.getSigners();
  // Use provided initial owner or fall back to signer
  const initialOwner = initialOwnerArg || (await signer.getAddress());
  console.log(`Deploying with signer: ${await signer.getAddress()}`);
  console.log(`Setting initial owner to: ${initialOwner}`);
  console.log(`Deploying with WOTSPlus at: ${wotsAddress}`);
  // Encode QuipFactory constructor parameters with WOTSPlus address
  const encodedParams = QuipFactory.interface.encodeDeploy([
    initialOwner,
    wotsAddress,
  ]);
  const factoryBytecodeWithParams = factoryBytecode + encodedParams.slice(2); // remove 0x prefix

  // Precompute QuipFactory address
  const factoryExpectedAddress = await computeAddress(
    factoryBytecodeWithParams,
    SALT,
    deployerAddress
  );
  const factoryAlreadyDeployed = await isContractDeployed(
    factoryExpectedAddress
  );

  let factoryAddress: string;
  if (factoryAlreadyDeployed) {
    console.log(`QuipFactory already deployed at: ${factoryExpectedAddress}`);
    factoryAddress = factoryExpectedAddress;
  } else {
    console.log("Deploying QuipFactory...");
    const factoryTx = await deployer.deploy(
      factoryBytecodeWithParams,
      hre.ethers.id(SALT),
      deployOptions
    );
    const factoryReceipt = await factoryTx.wait();
    const factoryDeployEvent = factoryReceipt?.logs.find(
      (log) =>
        log.topics[0] === deployer.interface.getEvent("Deploy")?.topicHash
    );
    factoryAddress = deployer.interface.parseLog({
      topics: factoryDeployEvent!.topics,
      data: factoryDeployEvent!.data,
    })!.args.addr;
    console.log(`QuipFactory deployed to: ${factoryAddress}`);
  }

  // After successful deployment, save addresses to tmp file
  const addresses = {
    Deployer: deployerAddress,
    WOTSPlus: wotsAddress,
    QuipFactory: factoryAddress,
  };

  // Write to tmp file
  fs.writeFileSync(TMP_ADDRESSES_FILE, JSON.stringify(addresses, null, 2));

  // Compare with existing file if it exists
  if (fs.existsSync(ADDRESSES_FILE)) {
    const existing = JSON.parse(fs.readFileSync(ADDRESSES_FILE, "utf8"));
    if (JSON.stringify(existing) !== JSON.stringify(addresses)) {
      console.error(
        "ERROR: Deployed addresses do not match existing addresses!"
      );
      console.error("Expected:", existing);
      console.error("Got:", addresses);
      process.exit(1);
    }
  } else {
    console.error(
      "WARNING: addresses.json does not exist. Create it from addresses.tmp.json if these addresses are correct."
    );
  }

  // Log all addresses for verification
  console.log("\nDeployed Addresses:");
  console.log("-------------------");
  console.log(`Network: ${network.name}`);
  console.log(`Deployer: ${deployerAddress}`);
  console.log(`WOTSPlus: ${wotsAddress}`);
  console.log(`QuipFactory: ${factoryAddress}`);
}

// Update the script execution to handle the new parameter
if (require.main === module) {
  main()
    .then(() => process.exit(0))
    .catch((error) => {
      console.error(error);
      process.exit(1);
    });
}

export { main as deploy };
