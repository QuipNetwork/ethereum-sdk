// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {Deployer} from "../contracts/Deployer.sol";
import {DeployWotsBase} from "./DeployWotsBase.sol";
import {IVettingFactory} from "./DeployHelpers.sol";

/**
 * @title DeployAllWots
 * @dev Deploys the full WOTS+ family through the existing Deployer (CREATE3):
 *      WOTSPlus library, the shared QuipFactory, the WOTSPlusImplementation wallet
 *      impl (vetted), and the QuipPaymaster (impl + proxy). Idempotent — re-runs
 *      skip already-deployed/vetted contracts. WOTS+ is vetted last, so
 *      `latestWalletImpl == WOTSPlusImplementation` afterward.
 *
 *      MUST run with `FOUNDRY_PROFILE=deploy` (QuipFactory + WOTSPlusImplementation
 *      link the WOTSPlus library). The PRIVATE_KEY must be the QuipFactory owner
 *      (vetting is owner-gated).
 *
 * Usage:
 *   FOUNDRY_PROFILE=deploy forge script script/DeployAllWots.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      - Operations / factory-owner key
 *   DEPLOYER_ADDRESS - Deployer contract (bootstrapped via DeployDeployer)
 *   FACTORY_OWNER    - Initial QuipFactory owner
 *   MAX_FEE          - Max wallet-creation fee (wei)
 *   PAYMASTER_OWNER  - Initial QuipPaymaster proxy owner
 */
contract DeployAllWots is DeployWotsBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address deployerAddr = vm.envAddress("DEPLOYER_ADDRESS");
        address factoryOwner = vm.envAddress("FACTORY_OWNER");
        uint256 maxFee = vm.envUint("MAX_FEE");
        address paymasterOwner = vm.envAddress("PAYMASTER_OWNER");

        _requireExists(deployerAddr, "Deployer");
        require(factoryOwner != address(0), "FACTORY_OWNER must be non-zero");
        require(maxFee != 0, "MAX_FEE must be non-zero");
        require(paymasterOwner != address(0), "PAYMASTER_OWNER must be non-zero");

        console.log("=== DeployAllWots ===");
        console.log("Deployer:", deployerAddr);
        address factory = _deployWotsAll(Deployer(deployerAddr), pk, factoryOwner, maxFee, paymasterOwner);

        console.log("=== Done ===");
        console.log("QuipFactory:", factory);
        console.log("latestWalletImpl:", IVettingFactory(factory).latestWalletImpl());
    }
}
