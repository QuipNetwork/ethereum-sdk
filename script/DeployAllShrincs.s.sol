// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {DeployShrincsBase} from "./DeployShrincsBase.sol";
import {IVettingFactory} from "./DeployHelpers.sol";

/**
 * @title DeployAllShrincs
 * @dev Deploys the full Shrincs family straight through CreateX (sender-guarded
 *      CREATE3): the ShrincsWallet impl (vetted on the shared WalletFactory) and
 *      the ShrincsPaymaster (impl + proxy, initialized with its verifier key).
 *      Idempotent. The Shrincs contracts have no library links, so this needs no
 *      `FOUNDRY_PROFILE=deploy`.
 *
 *      PREREQUISITE: the shared WalletFactory must already be deployed (run
 *      DeployWalletFactory or DeployAll first). PRIVATE_KEY must be the factory
 *      owner (vetting is owner-gated) AND the DEPLOY_OPERATOR (sender-guarded
 *      salts).
 *
 *      LATEST-IMPL SIDE EFFECT: vetting the ShrincsWallet sets the factory's
 *      `latestWalletImpl` to it, so `deployLatestWalletProxy` (the WOTS+ SDK's
 *      `createWallet`) would resolve to Shrincs afterward. If WOTS+ must remain the
 *      default, run DeployAll (which re-vets WOTS+ last) instead of this standalone
 *      script. The Shrincs SDK is unaffected — it always uses
 *      `deploySpecificWalletProxy`.
 *
 * Usage:
 *   forge script script/DeployAllShrincs.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY                     - Factory-owner key; MUST be DEPLOY_OPERATOR's
 *   DEPLOY_OPERATOR                 - Canonical deploy operator (sender-guarded salts)
 *   FACTORY_ADDRESS                 - Existing shared WalletFactory
 *   SHRINCS_PAYMASTER_OWNER         - Initial ShrincsPaymaster proxy owner
 *   SHRINCS_VERIFIER_COMMITMENT     - Verifier key bundle commitment (bytes32, non-zero)
 *   SHRINCS_VERIFIER_MAX_SIGNATURES - Verifier stateful budget (non-zero)
 *   SHRINCS_VERIFIER_PARAM_SET_ID   - Parameter-set enum (uint8, default 0)
 */
contract DeployAllShrincs is DeployShrincsBase {
    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        address operator = vm.envAddress("DEPLOY_OPERATOR");
        address factory = vm.envAddress("FACTORY_ADDRESS");

        _requireExists(factory, "WalletFactory");

        console.log("=== DeployAllShrincs ===");
        console.log("CreateX:        ", CREATEX);
        console.log("Deploy operator:", operator);
        console.log("WalletFactory:  ", factory);
        _deployShrincsAll(operator, pk, factory, _shrincsVerifierFromEnv());

        console.log("=== Done ===");
        console.log("latestWalletImpl (now Shrincs):", IVettingFactory(factory).latestWalletImpl());
    }
}
