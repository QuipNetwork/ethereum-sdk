// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {Deployer} from "../contracts/Deployer.sol";

/**
 * @title DeployAll
 * @dev Orchestrates deployment of WOTSPlus and QuipFactory via existing Deployer contract.
 *      The Deployer contract must already exist (deployed separately via DeployDeployer.s.sol).
 *
 * Usage:
 *   forge script script/DeployAll.s.sol --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY - Operations wallet private key
 *   DEPLOYER_ADDRESS - Deployer contract address
 */
contract DeployAll is Script {
    function run() external {
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        console.log("=== Quip Network Full Deployment ===");
        console.log("Deployer contract:", deployerAddr);
        require(deployerAddr.code.length > 0, "Deployer contract not found. Run DeployDeployer.s.sol first.");

        Deployer deployer = Deployer(deployerAddr);

        // --- Deploy WOTSPlus ---
        console.log("\n--- WOTSPlus ---");
        (bytes memory wotsBytecode, bytes32 wotsSalt, address wotsExpected) = _loadRelease("WOTSPlus.sol");

        address wotsAddr;
        if (wotsExpected.code.length > 0) {
            console.log("WOTSPlus already deployed at:", wotsExpected);
            wotsAddr = wotsExpected;
        } else {
            vm.startBroadcast(privateKey);
            wotsAddr = deployer.deploy(wotsBytecode, uint256(wotsSalt));
            vm.stopBroadcast();
            console.log("WOTSPlus deployed at:", wotsAddr);
        }

        // --- Deploy QuipFactory ---
        console.log("\n--- QuipFactory ---");
        (bytes memory factoryBytecode, bytes32 factorySalt, address factoryExpected) = _loadRelease("QuipFactory.sol");

        address factoryAddr;
        if (factoryExpected.code.length > 0) {
            console.log("QuipFactory already deployed at:", factoryExpected);
            factoryAddr = factoryExpected;
        } else {
            vm.startBroadcast(privateKey);
            factoryAddr = deployer.deploy(factoryBytecode, uint256(factorySalt));
            vm.stopBroadcast();
            console.log("QuipFactory deployed at:", factoryAddr);
        }

        // --- Summary ---
        console.log("\n=== Deployment Summary ===");
        console.log("Deployer:    ", deployerAddr);
        console.log("WOTSPlus:    ", wotsAddr);
        console.log("QuipFactory: ", factoryAddr);
    }

    function _loadRelease(string memory contractDir)
        internal
        view
        returns (bytes memory bytecode, bytes32 salt, address expectedAddr)
    {
        string memory latestJson = vm.readFile(
            string.concat("deployments/bytecode/", contractDir, "/latest.json")
        );
        string memory releaseFile = vm.parseJsonString(latestJson, ".file");
        string memory releaseJson = vm.readFile(
            string.concat("deployments/bytecode/", contractDir, "/", releaseFile)
        );

        bytecode = vm.parseJsonBytes(releaseJson, ".creationBytecode");
        salt = vm.parseJsonBytes32(releaseJson, ".salt");
        expectedAddr = vm.parseJsonAddress(releaseJson, ".address");
    }
}
