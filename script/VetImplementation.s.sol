// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {DeployHelpers, IVettingFactory} from "./DeployHelpers.sol";

/**
 * @title VetImplementation
 * @dev Ops utility: vets an already-deployed wallet implementation (any
 *      family) on the WalletFactory. Idempotent — an already-vetted impl is
 *      skipped, not reverted. The caller must be the factory owner.
 *
 *      NOTE: a successful vet sets the factory's `latestWalletImpl` to this
 *      impl — it becomes the `deployLatestWalletProxy` default.
 *
 * Usage:
 *   forge script script/VetImplementation.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
 *
 * Environment:
 *   PRIVATE_KEY     - Factory owner private key
 *   FACTORY_ADDRESS - WalletFactory contract address
 *   IMPLEMENTATION  - Deployed wallet implementation address to vet
 */
contract VetImplementation is DeployHelpers {
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address factoryAddr = vm.envAddress("FACTORY_ADDRESS");
        address impl = vm.envAddress("IMPLEMENTATION");

        _requireExists(factoryAddr, "WalletFactory");
        _requireExists(impl, "Implementation");

        IVettingFactory factory = IVettingFactory(factoryAddr);

        console.log("Factory:", factoryAddr);
        console.log("Factory owner:", factory.owner());
        console.log("Implementation:", impl);
        console.log("Implementation codehash:", vm.toString(impl.codehash));

        _vetIfNeeded(factoryAddr, privateKey, impl, "Implementation");

        console.log("Vetted code count:", factory.getVettedCodeCount());
        console.log("Latest wallet impl:", factory.latestWalletImpl());
    }
}
