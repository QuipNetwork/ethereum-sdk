// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {Deployer} from "../contracts/Deployer.sol";
import {QuipFactory} from "../contracts/QuipFactory.sol";

/**
 * @title DeployQuipFactory
 * @dev Deploys the QuipFactory via the Deployer contract using CREATE3
 *      (solady's `CREATE3.deployDeterministic`). Factory address depends only
 *      on (Deployer address, salt) — same on every chain, independent of
 *      constructor args. Owner / maxFee differ per chain but the address
 *      doesn't.
 *
 *      IMPORTANT: this script must be run with `FOUNDRY_PROFILE=deploy` so
 *      the QuipFactory bytecode has the WOTSPlus library linked at compile
 *      time. Without that, the bytecode contains an unlinked library
 *      reference and the deploy reverts.
 *
 * Usage:
 *   FOUNDRY_PROFILE=deploy forge script script/DeployQuipFactory.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      - Operations wallet private key
 *   DEPLOYER_ADDRESS - Deployer contract address (bootstrapped via DeployDeployer)
 *   FACTORY_OWNER    - Initial owner of the factory (controls vetImplementation)
 *   MAX_FEE          - Maximum wallet-creation fee in wei (e.g. 1000000000000000 = 0.001 ETH)
 */
contract DeployQuipFactory is Script {
    bytes32 internal constant SALT = keccak256("QUIP:QuipFactory:V1.1");

    function run() external {
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address factoryOwner = vm.envAddress("FACTORY_OWNER");
        uint256 maxFee = vm.envUint("MAX_FEE");

        require(deployerAddr.code.length > 0, "Deployer not deployed. Run DeployDeployer first.");
        require(factoryOwner != address(0), "FACTORY_OWNER must be non-zero");
        require(maxFee != 0, "MAX_FEE must be non-zero");

        address expectedAddr = CREATE3.predictDeterministicAddress(SALT, deployerAddr);
        console.log("Deployer:             ", deployerAddr);
        console.log("Factory owner:        ", factoryOwner);
        console.log("Max fee:              ", maxFee);
        console.log("Expected QuipFactory: ", expectedAddr);

        if (expectedAddr.code.length > 0) {
            console.log("\nQuipFactory already deployed. Skipping.");
            return;
        }

        bytes memory bytecode = abi.encodePacked(
            type(QuipFactory).creationCode,
            abi.encode(factoryOwner, maxFee)
        );
        console.log("Bytecode size:", bytecode.length, "bytes");

        vm.startBroadcast(privateKey);
        address deployed = Deployer(deployerAddr).deploy(bytecode, SALT);
        vm.stopBroadcast();

        require(deployed == expectedAddr, "QuipFactory address mismatch");
        require(QuipFactory(payable(deployed)).owner() == factoryOwner, "Factory owner mismatch");
        console.log("QuipFactory deployed at:", deployed);
    }
}
