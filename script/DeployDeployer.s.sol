// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {Deployer} from "../contracts/Deployer.sol";

/**
 * @title DeployDeployer
 * @dev Deploys the Deployer contract via CREATE at nonce=1 for deterministic address.
 *
 * Usage:
 *   forge script script/DeployDeployer.s.sol --rpc-url $RPC --private-key $DEPLOYER_PRIVATE_KEY --broadcast
 *
 * Environment:
 *   DEPLOYER_PRIVATE_KEY - One-time deployer wallet private key (must be at nonce=1)
 *   EXPECTED_DEPLOYER_ADDRESS - Expected address for validation
 */
contract DeployDeployer is Script {
    uint256 constant EXPECTED_NONCE = 1;

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployerWallet = vm.addr(deployerKey);

        console.log("Deployer Wallet:", deployerWallet);
        console.log("Current nonce:", vm.getNonce(deployerWallet));

        // Validate nonce
        require(
            vm.getNonce(deployerWallet) <= EXPECTED_NONCE,
            "CRITICAL: Nonce too high. Must use a fresh wallet."
        );

        // Advance nonce if needed (deploy placeholder contracts)
        vm.startBroadcast(deployerKey);

        while (vm.getNonce(deployerWallet) < EXPECTED_NONCE) {
            new Deployer(); // placeholder to advance nonce
        }

        // Deploy Deployer at the target nonce
        Deployer deployer = new Deployer();
        address deployerAddr = address(deployer);

        vm.stopBroadcast();

        console.log("Deployer deployed at:", deployerAddr);

        // Validate against expected address if provided
        try vm.envAddress("EXPECTED_DEPLOYER_ADDRESS") returns (address expected) {
            require(deployerAddr == expected, "Address mismatch!");
            console.log("Address matches expected.");
        } catch {
            // No expected address set, skip validation
        }
    }
}
