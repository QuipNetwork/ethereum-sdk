// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";

/**
 * @title PredictAddresses
 * @dev Computes CREATE3 addresses for all contracts without deploying anything.
 *      Mirrors Solady's CREATE3.predictDeterministicAddress(salt, deployer).
 *
 *      CREATE3 addresses depend only on the Deployer address and salt,
 *      not on bytecode. This means addresses are known before deployment.
 *
 * Usage:
 *   DEPLOYER_ADDRESS=0x... forge script script/PredictAddresses.s.sol
 *
 * Environment:
 *   DEPLOYER_ADDRESS - Deployer contract address (or predicted address)
 */
contract PredictAddresses is Script {
    function run() external view {
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        console.log("Deployer:", deployerAddr);
        console.log("");

        _predict(deployerAddr, "WOTSPlus");
        _predict(deployerAddr, "QuipFactory");
        _predict(deployerAddr, "QuipWallet");
    }

    function _predict(address deployer, string memory name) internal pure {
        bytes32 salt = keccak256(abi.encodePacked("QUIP:", name, ":V1"));
        address predicted = CREATE3.predictDeterministicAddress(salt, deployer);
        console.log(string.concat(name, ":"), predicted);
    }
}
