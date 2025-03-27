import hre from "hardhat";
import "dotenv/config";
import { addNetwork } from "./addNetwork";

const SALT = "QUIP";

async function computeAddress(bytecode: string, salt: string,
    deployerAddress: string): Promise<string> {
    const creationCode = bytecode;
    const hash = hre.ethers.keccak256(
        hre.ethers.solidityPacked(
            ["bytes1", "address", "bytes32", "bytes32"],
            [
                "0xff",
                deployerAddress,
                hre.ethers.id(salt),
                hre.ethers.keccak256(creationCode)
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
    const isHardhat = network.name === 'hardhat';

    // First verify the deployer exists
    const isDeployed = await isContractDeployed(deployerAddress);
    
    if (!isDeployed) {
        if (!isHardhat) {
            throw new Error(`Deployer contract not found at ${deployerAddress} on current network`);
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
    const deployerAddress = process.env.DEPLOYER_ADDRESS!;

    if (deployerAddress === undefined || deployerAddress.length !== 42) {
        throw new Error("DEPLOYER_ADDRESS not set or wrong length in .env");
    }

    // Load the deployer contract
    const deployer = await loadDeployer(deployerAddress);

    // Get the bytecode for WOTSPlus
    const WOTSPlus = await hre.ethers.getContractFactory("@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus");
    const wotsBytecode = WOTSPlus.bytecode;

    // Precompute WOTSPlus address
    const wotsExpectedAddress = await computeAddress(wotsBytecode, SALT, deployerAddress);
    const wotsAlreadyDeployed = await isContractDeployed(wotsExpectedAddress);
    
    let wotsAddress: string;
    if (wotsAlreadyDeployed) {
        console.log(`WOTSPlus already deployed at: ${wotsExpectedAddress}`);
        wotsAddress = wotsExpectedAddress;
    } else {
        console.log("Deploying WOTSPlus...");
        const wotsTx = await deployer.deploy(wotsBytecode, hre.ethers.id(SALT));
        const wotsReceipt = await wotsTx.wait();
        const wotsDeployEvent = wotsReceipt?.logs.find(
            log => log.topics[0] === deployer.interface.getEvent('Deploy')?.topicHash
        );
        wotsAddress = deployer.interface.parseLog({
            topics: wotsDeployEvent!.topics,
            data: wotsDeployEvent!.data
        })!.args.addr;
        console.log(`WOTSPlus deployed to: ${wotsAddress}`);
    }

    // Get the bytecode for QuipFactory
    const QuipFactory = await hre.ethers.getContractFactory("QuipFactory",
        {
            libraries: {
              "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol:WOTSPlus": wotsAddress
            }
        }
    );
    const factoryBytecode = QuipFactory.bytecode;
    
    // Encode QuipFactory constructor parameters with WOTSPlus address
    const encodedParams = QuipFactory.interface.encodeDeploy([wotsAddress]);
    const factoryBytecodeWithParams = factoryBytecode + encodedParams.slice(2); // remove 0x prefix

    // Precompute QuipFactory address
    const factoryExpectedAddress = await computeAddress(factoryBytecodeWithParams, SALT, deployerAddress);
    const factoryAlreadyDeployed = await isContractDeployed(factoryExpectedAddress);

    let factoryAddress: string;
    if (factoryAlreadyDeployed) {
        console.log(`QuipFactory already deployed at: ${factoryExpectedAddress}`);
        factoryAddress = factoryExpectedAddress;
    } else {
        console.log("Deploying QuipFactory...");
        const factoryTx = await deployer.deploy(factoryBytecodeWithParams, hre.ethers.id(SALT));
        const factoryReceipt = await factoryTx.wait();
        const factoryDeployEvent = factoryReceipt?.logs.find(
            log => log.topics[0] === deployer.interface.getEvent('Deploy')?.topicHash
        );
        factoryAddress = deployer.interface.parseLog({
            topics: factoryDeployEvent!.topics,
            data: factoryDeployEvent!.data
        })!.args.addr;
        console.log(`QuipFactory deployed to: ${factoryAddress}`);
    }

    // Log all addresses for verification
    console.log("\nDeployed Addresses:");
    console.log("-------------------");
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
