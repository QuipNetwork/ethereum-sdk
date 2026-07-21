// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {DeployConstants} from "./Constants.sol";
import {CreateXHelpers} from "./CreateXHelpers.sol";

/**
 * @title PredictAddresses
 * @dev Pure-view script: prints the CREATE3 address every Quip contract will
 *      land at on any chain. No RPC required.
 *
 *      LIVE contracts (WalletFactory, ShrincsWallet, ShrincsPaymaster) deploy
 *      straight through CreateX with SENDER-GUARDED salts, so their addresses
 *      are a function of (CreateX, DEPLOY_OPERATOR, salt) — set `DEPLOY_OPERATOR`
 *      to compute them (without it those rows are skipped with a notice).
 *
 *      SUNSET WOTS+-era contracts (WOTSPlus, WOTSPlusImplementation,
 *      QuipPaymaster) keep their historical derivation through the deprecated
 *      `Deployer` (itself CreateX-deployed on an unguarded salt) — those rows
 *      need no env vars. `DEPLOYER_ADDRESS` overrides the canonical Deployer.
 *
 * Usage:
 *   DEPLOY_OPERATOR=0x... forge script script/PredictAddresses.s.sol
 *   forge script script/PredictAddresses.s.sol            # WOTS+-era rows only
 */
contract PredictAddresses is CreateXHelpers {
    bytes32 internal constant DEPLOYER_SALT = keccak256("QUIP:Deployer:V1");

    function run() external view {
        // -- live contracts: CreateX-direct, sender-guarded ------------------
        address operator;
        try vm.envAddress("DEPLOY_OPERATOR") returns (address op) {
            operator = op;
        } catch {
            console.log("DEPLOY_OPERATOR not set - skipping live-contract rows");
            console.log("(live canonical addresses are a function of the operator address)");
        }
        if (operator != address(0)) {
            console.log("CreateX:        ", CREATEX);
            console.log("Deploy operator:", operator);
            _predictLive(operator, "WalletFactory (impl)", DeployConstants.FACTORY_IMPL_SALT);
            _predictLive(operator, "WalletFactory (proxy)", DeployConstants.FACTORY_PROXY_SALT);
            // Impl salts bind the verifier scheme tag (the verifier's PROFILE_TAG ==
            // SHRINCSParams.PROFILE_ID) — see DeployConstants: a different
            // cryptographic scheme must land at a different implementation address.
            _predictLiveRaw(operator, "ShrincsWallet (impl)", DeployConstants.shrincsWalletSalt());
            _predictLiveRaw(
                operator, "ShrincsPaymaster (impl)", DeployConstants.shrincsPaymasterImplSalt()
            );
            _predictLive(
                operator, "ShrincsPaymaster (proxy)", DeployConstants.SHRINCS_PAYMASTER_PROXY_SALT
            );
        }
        console.log("");

        // -- sunset WOTS+ era: derived through the deprecated Deployer -------
        address deployerAddr;
        try vm.envAddress("DEPLOYER_ADDRESS") returns (address override_) {
            deployerAddr = override_;
            console.log("Deployer (env override):  ", deployerAddr);
        } catch {
            // CreateX uses the same proxy initcode as solady's CREATE3, so the
            // Deployer's address is predictable purely off-chain via solady's
            // predictor with `deployer = CreateX` (unguarded-salt fallback:
            // guardedSalt = keccak256(abi.encode(salt))).
            bytes32 guardedSalt = keccak256(abi.encode(DEPLOYER_SALT));
            deployerAddr = CREATE3.predictDeterministicAddress(guardedSalt, CREATEX);
            console.log("Deployer (canonical):     ", deployerAddr);
        }
        _predictWots(deployerAddr, "WOTSPlus", keccak256("QUIP:WOTSPlus:V1.1"));
        _predictWots(deployerAddr, "WOTSPlusImplementation (impl)", keccak256("QUIP:WOTSPlusImplementation:V1.1"));
        _predictWots(deployerAddr, "QuipPaymaster (impl)", keccak256("QUIP:QuipPaymaster:Impl:V1.1"));
        _predictWots(deployerAddr, "QuipPaymaster (proxy)", keccak256("QUIP:QuipPaymaster:Proxy:V1.1"));

        // Not deployed by this repo — the canonical hashsigs-solidity CREATE3
        // verifier the Shrincs impls pin (see DeployConstants).
        console.log("SHRINCS256sKeccak (pinned):", DeployConstants.SHRINCS_EXTERNAL_VERIFIER);
    }

    function _predictLive(address operator, string memory name, string memory saltString) internal pure {
        console.log(string.concat(name, ":"), _predictCreateX(operator, bytes(saltString)));
    }

    function _predictLiveRaw(address operator, string memory name, bytes memory saltPreimage) internal pure {
        console.log(string.concat(name, ":"), _predictCreateX(operator, saltPreimage));
    }

    function _predictWots(address deployer, string memory name, bytes32 salt) internal pure {
        console.log(string.concat(name, ":"), CREATE3.predictDeterministicAddress(salt, deployer));
    }
}
