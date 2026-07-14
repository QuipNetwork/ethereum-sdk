// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {Deployer} from "../contracts/Deployer.sol";

/**
 * @title DeployWOTSPlus
 * @dev Deploys the WOTSPlus library via the Deployer contract using CREATE3
 *      (solady's `CREATE3.deployDeterministic`).
 *
 *      The library's address depends only on (Deployer address, salt). Same
 *      Deployer + same salt on every chain → same WOTSPlus address. WOTSPlus
 *      has no constructor and no library dependencies of its own, so the
 *      creation bytecode is fully self-contained — no FOUNDRY_PROFILE
 *      gymnastics required.
 *
 * Usage:
 *   forge script script/DeployWOTSPlus.s.sol --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      - Operations wallet private key
 *   DEPLOYER_ADDRESS - Deployer contract address (bootstrapped via DeployDeployer)
 */
contract DeployWOTSPlus is Script {
    bytes32 internal constant SALT = keccak256("QUIP:WOTSPlus:V1.1");

    function run() external {
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        uint256 privateKey = vm.envUint("PRIVATE_KEY");

        require(deployerAddr.code.length > 0, "Deployer not deployed. Run DeployDeployer first.");

        address expectedAddr = CREATE3.predictDeterministicAddress(SALT, deployerAddr);
        console.log("Deployer:          ", deployerAddr);
        console.log("Expected WOTSPlus: ", expectedAddr);

        if (expectedAddr.code.length > 0) {
            console.log("\nWOTSPlus already deployed. Skipping.");
            return;
        }

        bytes memory bytecode = type(WOTSPlus).creationCode;
        console.log("Bytecode size:", bytecode.length, "bytes");

        vm.startBroadcast(privateKey);
        address deployed = Deployer(deployerAddr).deploy(bytecode, SALT);
        vm.stopBroadcast();

        require(deployed == expectedAddr, "WOTSPlus address mismatch");
        console.log("WOTSPlus deployed at:", deployed);
    }
}
