// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {WalletFactory} from "../contracts/WalletFactory.sol";
import {DeployConstants} from "./Constants.sol";
import {DeployFactoryBase} from "./DeployFactoryBase.sol";

/**
 * @title DeployFactory
 * @dev STEP 1 of 2 (run `02_DeployShrincs.s.sol` next). Deploys the
 *      WalletFactory as implementation + ERC-1967 proxy straight through
 *      CreateX using sender-guarded CREATE3 salts (`CreateXHelpers`).
 *      Addresses depend on (CreateX, DEPLOY_OPERATOR, salt) — the same on every
 *      chain for the same operator, independent of constructor args, and
 *      squat-proof: only the operator key can consume the salts. Idempotent.
 *
 *      The PROXY address is the permanent factory identity: wallets bake it
 *      in as an immutable and CREATE3 wallet addressing derives from it, so
 *      it survives implementation upgrades.
 *
 *      No `FOUNDRY_PROFILE=deploy` needed (the factory links no libraries).
 *
 * Usage:
 *   forge script script/01_DeployFactory.s.sol \
 *       --rpc-url $RPC --private-key $PRIVATE_KEY --broadcast --verify
 *
 * Environment:
 *   PRIVATE_KEY      - MUST be the DEPLOY_OPERATOR's key (sender-guarded salts)
 *   DEPLOY_OPERATOR  - Canonical deploy operator; every canonical address is a
 *                      function of this address — guard the key accordingly
 *   FACTORY_OWNER    - Initial owner of the factory (controls vetting, fees, upgrades)
 *   MAX_FEE          - Maximum wallet-creation fee in wei (e.g. 1000000000000000 = 0.001 ETH)
 */
contract DeployFactory is DeployFactoryBase {
    function run() external {
        uint256 privateKey = vm.envUint("PRIVATE_KEY");
        address operator = vm.envAddress("DEPLOY_OPERATOR");
        address factoryOwner = vm.envAddress("FACTORY_OWNER");
        uint256 maxFee = vm.envUint("MAX_FEE");

        // Fail fast, before any deploy step runs half-way. The canonical-operator
        // check comes FIRST: the key check below only proves the env var and the
        // key agree with each other, which a stale operator would also satisfy.
        require(
            operator == DeployConstants.CANONICAL_OPERATOR,
            "DEPLOY_OPERATOR is not the canonical operator"
        );
        require(vm.addr(privateKey) == operator, "PRIVATE_KEY is not DEPLOY_OPERATOR's key");
        require(CREATEX.code.length > 0, "CreateX not deployed on this chain");
        require(factoryOwner != address(0), "FACTORY_OWNER must be non-zero");
        require(maxFee != 0, "MAX_FEE must be non-zero");

        console.log("=== 01_DeployFactory ===");
        console.log("CreateX:        ", CREATEX);
        console.log("Deploy operator:", operator);
        console.log("Factory owner:  ", factoryOwner);
        console.log("Max fee:        ", maxFee);

        address proxy = _deployFactoryViaCreateX(operator, privateKey, factoryOwner, maxFee);

        require(WalletFactory(payable(proxy)).owner() == factoryOwner, "Factory owner mismatch");
        require(WalletFactory(payable(proxy)).MAX_FEE() == maxFee, "Factory MAX_FEE mismatch");

        console.log("=== 01_DeployFactory done ===");
        console.log(
            "WalletFactory impl:  ",
            _predictCreateX(operator, bytes(DeployConstants.FACTORY_IMPL_SALT))
        );
        console.log("WalletFactory proxy: ", proxy);
        console.log("Next: 02_DeployShrincs.s.sol");
    }
}
