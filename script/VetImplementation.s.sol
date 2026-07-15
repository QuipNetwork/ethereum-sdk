// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {WalletFactory} from "../contracts/WalletFactory.sol";

/**
 * @title VetImplementation
 * @dev Vets an already-deployed WOTSPlusImplementation implementation on the WalletFactory.
 *      The caller must be the factory owner.
 *
 * Usage:
 *   forge script script/VetImplementation.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
 *
 * Environment:
 *   PRIVATE_KEY - Factory owner private key
 *   FACTORY_ADDRESS - WalletFactory contract address
 *   IMPLEMENTATION - Deployed WOTSPlusImplementation implementation address to vet
 */
contract VetImplementation is Script {
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address factoryAddr = vm.envAddress("FACTORY_ADDRESS");
        address impl = vm.envAddress("IMPLEMENTATION");

        require(factoryAddr.code.length > 0, "Factory not deployed");
        require(impl.code.length > 0, "Implementation not deployed");

        WalletFactory factory = WalletFactory(payable(factoryAddr));

        console.log("Factory:", factoryAddr);
        console.log("Factory owner:", factory.owner());
        console.log("Implementation:", impl);
        console.log("Implementation codehash:", vm.toString(impl.codehash));

        vm.startBroadcast(privateKey);
        factory.vetImplementation(impl);
        vm.stopBroadcast();

        console.log("Vetted code count:", factory.getVettedCodeCount());
        console.log("Latest wallet impl:", factory.latestWalletImpl());
    }
}
