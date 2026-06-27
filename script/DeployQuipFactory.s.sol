// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {Deployer} from "../contracts/Deployer.sol";

/**
 * @title DeployQuipFactory
 * @dev Deploys QuipFactory via Deployer contract using CREATE2.
 *      Uses stored release bytecode from deployments/bytecode/ for deterministic addresses.
 *
 * Usage:
 *   forge script script/DeployQuipFactory.s.sol --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast
 *
 * Environment:
 *   PRIVATE_KEY - Operations wallet private key
 *   DEPLOYER_ADDRESS - Deployer contract address
 */
contract DeployQuipFactory is Script {
    function run() external {
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        console.log("Deployer contract:", deployerAddr);

        // Load release bytecode
        string memory json = vm.readFile("deployments/bytecode/QuipFactory.sol/latest.json");
        string memory releaseFile = vm.parseJsonString(json, ".file");
        string memory releaseJson = vm.readFile(
            string.concat("deployments/bytecode/QuipFactory.sol/", releaseFile)
        );

        bytes memory creationBytecode = vm.parseJsonBytes(releaseJson, ".creationBytecode");
        bytes32 salt = vm.parseJsonBytes32(releaseJson, ".salt");
        address expectedAddress = vm.parseJsonAddress(releaseJson, ".address");

        console.log("Expected QuipFactory address:", expectedAddress);
        console.log("Bytecode size:", creationBytecode.length, "bytes");

        // Check if already deployed
        if (expectedAddress.code.length > 0) {
            console.log("QuipFactory already deployed. Skipping.");
            return;
        }

        // Verify WOTSPlus is deployed
        string memory wotsJson = vm.readFile("deployments/bytecode/WOTSPlus.sol/latest.json");
        string memory wotsFile = vm.parseJsonString(wotsJson, ".file");
        string memory wotsReleaseJson = vm.readFile(
            string.concat("deployments/bytecode/WOTSPlus.sol/", wotsFile)
        );
        address wotsAddress = vm.parseJsonAddress(wotsReleaseJson, ".address");
        require(wotsAddress.code.length > 0, "WOTSPlus not deployed. Deploy it first.");

        Deployer deployer = Deployer(deployerAddr);

        vm.startBroadcast(privateKey);
        address factoryAddr = deployer.deploy(creationBytecode, salt);
        vm.stopBroadcast();

        console.log("QuipFactory deployed at:", factoryAddr);

        if (factoryAddr != expectedAddress) {
            console.log("WARNING: Address mismatch! Expected:", expectedAddress);
        }
    }
}
