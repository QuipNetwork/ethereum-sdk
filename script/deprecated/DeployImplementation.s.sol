// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {Deployer} from "../../contracts/Deployer.sol";
import {WOTSPlusImplementation} from "../../contracts/deprecated/wots/WOTSPlusImplementation.sol";

/**
 * @title DeployImplementation
 * @dev Deploys a WOTSPlusImplementation implementation via CREATE3 through the Deployer contract.
 *
 *      IMPORTANT: This script must be run with FOUNDRY_PROFILE=deploy so that the
 *      WOTSPlus library is linked at the correct CREATE3 address (configured in
 *      foundry.toml [profile.deploy] libraries). Without this, the bytecode will
 *      contain unlinked library references and the deployment will fail.
 *
 *      type(WOTSPlusImplementation).creationCode is linked at compile time via the profile's
 *      libraries config. The resulting bytecode is deployed through the Deployer's
 *      CREATE3 for a deterministic address.
 *
 * Usage:
 *   FOUNDRY_PROFILE=deploy forge script script/DeployImplementation.s.sol \
 *       --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
 *
 * Environment:
 *   PRIVATE_KEY - Operations wallet private key
 *   DEPLOYER_ADDRESS - Deployer contract address
 *   FACTORY_ADDRESS - WalletFactory contract address (WOTSPlusImplementation constructor arg)
 */
contract DeployImplementation is Script {
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        address factoryAddr = vm.envAddress("FACTORY_ADDRESS");

        require(deployerAddr.code.length > 0, "Deployer not deployed");
        require(factoryAddr.code.length > 0, "Factory not deployed");

        Deployer deployer = Deployer(deployerAddr);

        bytes32 salt = keccak256(abi.encodePacked("QUIP:WOTSPlusImplementation:V1.1"));
        address expectedAddress = CREATE3.predictDeterministicAddress(salt, deployerAddr);

        console.log("Deployer:", deployerAddr);
        console.log("Factory:", factoryAddr);
        console.log("Expected implementation:", expectedAddress);

        if (expectedAddress.code.length > 0) {
            console.log("Implementation already deployed. Skipping.");
            return;
        }

        bytes memory bytecode =
            abi.encodePacked(type(WOTSPlusImplementation).creationCode, abi.encode(payable(factoryAddr)));
        console.log("Bytecode size:", bytecode.length, "bytes");

        vm.startBroadcast(privateKey);
        address impl = deployer.deploy(bytecode, salt);
        vm.stopBroadcast();

        console.log("Implementation deployed at:", impl);
        if (impl != expectedAddress) {
            console.log("WARNING: Address mismatch! Expected:", expectedAddress);
        }
    }
}
