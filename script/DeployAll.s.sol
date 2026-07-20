// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
// Deliberate live->deprecated imports: deploy-all still provisions the sunset WOTS+
// family alongside SHRINCS (operational tooling, not runtime code). The WOTS+ era
// deploys through the deprecated Deployer hop to preserve its historical addresses;
// live contracts deploy straight through CreateX.
import {Deployer} from "../contracts/deprecated/Deployer.sol";
import {DeployWotsBase} from "./deprecated/DeployWotsBase.sol";
import {DeployShrincsBase} from "./DeployShrincsBase.sol";
import {DeployFactoryBase} from "./DeployFactoryBase.sol";
import {IVettingFactory} from "./DeployHelpers.sol";

/**
 * @title DeployAll
 * @dev Full Quip deployment: the WalletFactory (CreateX sender-guarded CREATE3),
 *      BOTH wallet families (WOTSPlusImplementation and ShrincsWallet, each
 *      vetted), and BOTH paymasters (QuipPaymaster and ShrincsPaymaster).
 *      Idempotent — re-runs skip already-deployed/vetted contracts.
 *
 *      Deploy mechanisms differ by era:
 *      - LIVE (WalletFactory, ShrincsWallet, ShrincsPaymaster): CreateX-direct,
 *        sender-guarded salts — PRIVATE_KEY must be DEPLOY_OPERATOR's key.
 *      - SUNSET WOTS+ (WOTSPlus lib, WOTSPlusImplementation, QuipPaymaster):
 *        through the deprecated `Deployer` at DEPLOYER_ADDRESS, preserving the
 *        family's historical Deployer-derived addresses.
 *
 *      VETTING ORDER: the Shrincs impl is vetted first and the WOTS+ impl LAST, so
 *      `latestWalletImpl == WOTSPlusImplementation` on completion — the WOTS+ SDK's
 *      `createWallet` (which uses `deployLatestWalletProxy`) keeps working, and the
 *      Shrincs SDK reaches its impl via `deploySpecificWalletProxy` regardless. To
 *      instead make Shrincs the default `latest`, swap the two `*ImplAndVet` calls
 *      below (a deliberate policy change — WOTS+ `createWallet` would then revert).
 *
 *      MUST run with `FOUNDRY_PROFILE=deploy` (WOTSPlusImplementation links the
 *      WOTSPlus library). PRIVATE_KEY must be the WalletFactory owner AND the
 *      DEPLOY_OPERATOR.
 *
 * Usage:
 *   FOUNDRY_PROFILE=deploy forge script script/DeployAll.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      DEPLOY_OPERATOR  DEPLOYER_ADDRESS  FACTORY_OWNER  MAX_FEE
 *   PAYMASTER_OWNER  SHRINCS_PAYMASTER_OWNER  SHRINCS_VERIFIER_COMMITMENT
 *   SHRINCS_VERIFIER_MAX_SIGNATURES  [SHRINCS_VERIFIER_PARAM_SET_ID=0]
 */
contract DeployAll is DeployWotsBase, DeployShrincsBase, DeployFactoryBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address operator = vm.envAddress("DEPLOY_OPERATOR");
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
        console.log("CreateX (live contracts):   ", CREATEX);
        console.log("Deploy operator:            ", operator);
        console.log("Deployer (sunset WOTS+ era):", deployerAddr);

        // 1. Live shared infra: WalletFactory via CreateX.
        console.log("-- shared infra --");
        address factory = _deployFactoryViaCreateX(operator, pk, factoryOwner, maxFee);

        // 2. Shrincs family via CreateX (vetted FIRST so it is not `latest`).
        console.log("-- shrincs --");
        _deployShrincsImplAndVet(operator, pk, factory);
        _deployShrincsPaymaster(operator, pk, verifier);

        // 3. Sunset WOTS+ family via the deprecated Deployer (impl vetted LAST
        //    -> latestWalletImpl == WOTSPlusImplementation). The WOTSPlus library
        //    is WOTS+-era infra and stays on its historical Deployer derivation.
        console.log("-- wots+ (sunset) --");
        _deployWotsPlusLib(deployer, pk);
        address wotsImpl = _deployWotsImplAndVet(deployer, pk, factory);
        _deployQuipPaymaster(deployer, pk, paymasterOwner);

        address latest = IVettingFactory(factory).latestWalletImpl();
        require(latest == wotsImpl, "latestWalletImpl is not WOTSPlusImplementation");

        console.log("=== Done ===");
        console.log("WalletFactory:   ", factory);
        console.log("latestWalletImpl:", latest, "(WOTSPlusImplementation)");
    }
}
