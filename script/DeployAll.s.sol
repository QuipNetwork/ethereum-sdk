// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {Deployer} from "../contracts/Deployer.sol";
// Deliberate live->deprecated import: deploy-all still provisions the sunset WOTS+
// family alongside SHRINCS (operational tooling, not runtime code).
import {DeployWotsBase} from "./deprecated/DeployWotsBase.sol";
import {DeployShrincsBase} from "./DeployShrincsBase.sol";
import {IVettingFactory} from "./DeployHelpers.sol";

/**
 * @title DeployAll
 * @dev Full Quip deployment through the existing Deployer (CREATE3): the shared
 *      WOTSPlus library + QuipFactory, BOTH wallet families (WOTSPlusImplementation
 *      and ShrincsWallet, each vetted), and BOTH paymasters (QuipPaymaster and
 *      ShrincsPaymaster). Idempotent — re-runs skip already-deployed/vetted
 *      contracts.
 *
 *      VETTING ORDER: the Shrincs impl is vetted first and the WOTS+ impl LAST, so
 *      `latestWalletImpl == WOTSPlusImplementation` on completion — the WOTS+ SDK's
 *      `createWallet` (which uses `deployLatestWalletProxy`) keeps working, and the
 *      Shrincs SDK reaches its impl via `deploySpecificWalletProxy` regardless. To
 *      instead make Shrincs the default `latest`, swap the two `*ImplAndVet` calls
 *      below (a deliberate policy change — WOTS+ `createWallet` would then revert).
 *
 *      MUST run with `FOUNDRY_PROFILE=deploy` (WOTSPlusImplementation links the
 *      WOTSPlus library). PRIVATE_KEY must be the QuipFactory owner.
 *
 * Usage:
 *   FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      DEPLOYER_ADDRESS  FACTORY_OWNER  MAX_FEE  PAYMASTER_OWNER
 *   SHRINCS_PAYMASTER_OWNER  SHRINCS_VERIFIER_COMMITMENT
 *   SHRINCS_VERIFIER_MAX_SIGNATURES  [SHRINCS_VERIFIER_PARAM_SET_ID=0]
 */
contract DeployAll is DeployWotsBase, DeployShrincsBase {
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

        Deployer deployer = Deployer(deployerAddr);
        ShrincsVerifier memory verifier = _shrincsVerifierFromEnv();

        console.log("=== DeployAll (WOTS+ and Shrincs) ===");
        console.log("Deployer:", deployerAddr);

        // 1. Shared infra: WOTSPlus library + QuipFactory.
        console.log("-- shared infra --");
        _deployWotsPlusLib(deployer, pk);
        address factory = _deployFactory(deployer, pk, factoryOwner, maxFee);

        // 2. Shrincs family (vetted FIRST so it is not `latest`).
        console.log("-- shrincs --");
        _deployShrincsImplAndVet(deployer, pk, factory);
        _deployShrincsPaymaster(deployer, pk, verifier);

        // 3. WOTS+ family (impl vetted LAST -> latestWalletImpl == WOTSPlusImplementation).
        console.log("-- wots+ --");
        address wotsImpl = _deployWotsImplAndVet(deployer, pk, factory);
        _deployQuipPaymaster(deployer, pk, paymasterOwner);

        address latest = IVettingFactory(factory).latestWalletImpl();
        require(latest == wotsImpl, "latestWalletImpl is not WOTSPlusImplementation");

        console.log("=== Done ===");
        console.log("QuipFactory:     ", factory);
        console.log("latestWalletImpl:", latest, "(WOTSPlusImplementation)");
    }
}
