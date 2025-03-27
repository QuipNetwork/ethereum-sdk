"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const hardhat_1 = __importDefault(require("hardhat"));
require("dotenv/config");
const addNetwork_1 = require("./addNetwork");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const SALT = "QUIP";
const ADDRESSES_FILE = path_1.default.join(__dirname, '../src/addresses.json');
const TMP_ADDRESSES_FILE = path_1.default.join(__dirname, '../src/addresses.tmp.json');
async function computeAddress(bytecode, salt, deployerAddress) {
    const creationCode = bytecode;
    const hash = hardhat_1.default.ethers.keccak256(hardhat_1.default.ethers.solidityPacked(["bytes1", "address", "bytes32", "bytes32"], [
        "0xff",
        deployerAddress,
        hardhat_1.default.ethers.id(salt),
        hardhat_1.default.ethers.keccak256(creationCode)
    ]));
    return hardhat_1.default.ethers.getAddress(`0x${hash.slice(-40)}`);
}
async function isContractDeployed(address) {
    const code = await hardhat_1.default.ethers.provider.getCode(address);
    return code !== "0x";
}
async function loadDeployer(deployerAddress) {
    const network = await hardhat_1.default.ethers.provider.getNetwork();
    const isHardhat = network.name === 'hardhat';
    // First verify the deployer exists
    const isDeployed = await isContractDeployed(deployerAddress);
    if (!isDeployed) {
        if (!isHardhat) {
            throw new Error(`Deployer contract not found at ${deployerAddress} on current network`);
        }
        // On hardhat network, run addNetwork to deploy the Deployer contract
        await (0, addNetwork_1.addNetwork)();
    }
    // Get the contract instance
    const deployer = await hardhat_1.default.ethers.getContractAt("Deployer", deployerAddress);
    console.log(`Found Deployer contract at: ${deployerAddress}`);
    return deployer;
}
async function main() {
    const network = await hardhat_1.default.ethers.provider.getNetwork();
    const deployerAddress = process.env.DEPLOYER_ADDRESS;
    if (deployerAddress === undefined || deployerAddress.length !== 42) {
        throw new Error("DEPLOYER_ADDRESS not set or wrong length in .env");
    }
    // Load the deployer contract
    const deployer = await loadDeployer(deployerAddress);
    // Get the bytecode for WOTSPlus
    const WOTSPlus = await hardhat_1.default.ethers.getContractFactory("@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus");
    const wotsBytecode = WOTSPlus.bytecode;
    // Precompute WOTSPlus address
    const wotsExpectedAddress = await computeAddress(wotsBytecode, SALT, deployerAddress);
    const wotsAlreadyDeployed = await isContractDeployed(wotsExpectedAddress);
    let wotsAddress;
    if (wotsAlreadyDeployed) {
        console.log(`WOTSPlus already deployed at: ${wotsExpectedAddress}`);
        wotsAddress = wotsExpectedAddress;
    }
    else {
        console.log("Deploying WOTSPlus...");
        const wotsTx = await deployer.deploy(wotsBytecode, hardhat_1.default.ethers.id(SALT));
        const wotsReceipt = await wotsTx.wait();
        const wotsDeployEvent = wotsReceipt?.logs.find(log => log.topics[0] === deployer.interface.getEvent('Deploy')?.topicHash);
        wotsAddress = deployer.interface.parseLog({
            topics: wotsDeployEvent.topics,
            data: wotsDeployEvent.data
        }).args.addr;
        console.log(`WOTSPlus deployed to: ${wotsAddress}`);
    }
    // Get the bytecode for QuipFactory
    const QuipFactory = await hardhat_1.default.ethers.getContractFactory("QuipFactory", {
        libraries: {
            "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus": wotsAddress
        }
    });
    const factoryBytecode = QuipFactory.bytecode;
    // Encode QuipFactory constructor parameters with WOTSPlus address
    const encodedParams = QuipFactory.interface.encodeDeploy([wotsAddress]);
    const factoryBytecodeWithParams = factoryBytecode + encodedParams.slice(2); // remove 0x prefix
    // Precompute QuipFactory address
    const factoryExpectedAddress = await computeAddress(factoryBytecodeWithParams, SALT, deployerAddress);
    const factoryAlreadyDeployed = await isContractDeployed(factoryExpectedAddress);
    let factoryAddress;
    if (factoryAlreadyDeployed) {
        console.log(`QuipFactory already deployed at: ${factoryExpectedAddress}`);
        factoryAddress = factoryExpectedAddress;
    }
    else {
        console.log("Deploying QuipFactory...");
        const factoryTx = await deployer.deploy(factoryBytecodeWithParams, hardhat_1.default.ethers.id(SALT));
        const factoryReceipt = await factoryTx.wait();
        const factoryDeployEvent = factoryReceipt?.logs.find(log => log.topics[0] === deployer.interface.getEvent('Deploy')?.topicHash);
        factoryAddress = deployer.interface.parseLog({
            topics: factoryDeployEvent.topics,
            data: factoryDeployEvent.data
        }).args.addr;
        console.log(`QuipFactory deployed to: ${factoryAddress}`);
    }
    // After successful deployment, save addresses to tmp file
    const addresses = {
        WOTSPlus: wotsAddress,
        QuipFactory: factoryAddress
    };
    // Write to tmp file
    fs_1.default.writeFileSync(TMP_ADDRESSES_FILE, JSON.stringify(addresses, null, 2));
    // Compare with existing file if it exists
    if (fs_1.default.existsSync(ADDRESSES_FILE)) {
        const existing = JSON.parse(fs_1.default.readFileSync(ADDRESSES_FILE, 'utf8'));
        if (JSON.stringify(existing) !== JSON.stringify(addresses)) {
            console.error('ERROR: Deployed addresses do not match existing addresses!');
            console.error('Expected:', existing);
            console.error('Got:', addresses);
            process.exit(1);
        }
    }
    else {
        console.error('WARNING: addresses.json does not exist. Create it from addresses.tmp.json if these addresses are correct.');
    }
    // Log all addresses for verification
    console.log("\nDeployed Addresses:");
    console.log("-------------------");
    console.log(`Network: ${network.name}`);
    console.log(`Deployer: ${deployerAddress}`);
    console.log(`WOTSPlus: ${wotsAddress}`);
    console.log(`QuipFactory: ${factoryAddress}`);
}
main()
    .then(() => process.exit(0))
    .catch((error) => {
    console.error(error);
    process.exit(1);
});
