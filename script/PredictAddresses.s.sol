// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Script, console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

/**
 * @title PredictAddresses
 * @dev Pure-view script: prints the CREATE3 address every Quip contract will
 *      land at on any chain — no env vars required.
 *
 *      The Deployer address itself is derived from CreateX + the
 *      `DEPLOYER_SALT`, matching how `DeployDeployer.s.sol` bootstraps it.
 *      All downstream addresses (WOTSPlus, QuipFactory, WOTSPlusImplementation impl,
 *      QuipPaymaster impl + proxy) are derived through that Deployer +
 *      their respective salts via solady's CREATE3.
 *
 *      Override path: if you want predictions against a Deployer deployed
 *      with a non-canonical salt (e.g. an old v0 instance), set
 *      `DEPLOYER_ADDRESS` in the environment and the script uses that
 *      instead of recomputing.
 *
 * Usage:
 *   forge script script/PredictAddresses.s.sol
 *   DEPLOYER_ADDRESS=0x... forge script script/PredictAddresses.s.sol  # override
 */
contract PredictAddresses is Script {
    address internal constant CREATEX = 0xba5Ed099633D3B313e4D5F7bdc1305d3c28ba5Ed;
    bytes32 internal constant DEPLOYER_SALT = keccak256("QUIP:Deployer:V1");

    function run() external view {
        address deployerAddr;
        try vm.envAddress("DEPLOYER_ADDRESS") returns (address override_) {
            deployerAddr = override_;
            console.log("Deployer (env override):  ", deployerAddr);
        } catch {
            // CreateX uses the same proxy initcode as solady's CREATE3,
            // so we can predict the Deployer's address purely off-chain
            // via solady's predictor with `deployer = CreateX`.
            bytes32 guardedSalt = keccak256(abi.encode(DEPLOYER_SALT));
            deployerAddr = CREATE3.predictDeterministicAddress(guardedSalt, CREATEX);
            console.log("Deployer (canonical):     ", deployerAddr);
        }
        console.log("");

        _predict(deployerAddr, "WOTSPlus", keccak256("QUIP:WOTSPlus:V1.1"));
        _predict(deployerAddr, "QuipFactory", keccak256("QUIP:QuipFactory:V1.1"));
        _predict(deployerAddr, "WOTSPlusImplementation (impl)", keccak256("QUIP:WOTSPlusImplementation:V1.1"));
        _predict(deployerAddr, "QuipPaymaster (impl)", keccak256("QUIP:QuipPaymaster:Impl:V1.1"));
        _predict(deployerAddr, "QuipPaymaster (proxy)", keccak256("QUIP:QuipPaymaster:Proxy:V1.1"));
        // Impl salts bind the verifier scheme tag (the verifier's PROFILE_TAG ==
        // SHRINCSParams.PROFILE_ID) — see DeployShrincsBase: a different
        // cryptographic scheme must land at a different implementation address.
        _predict(
            deployerAddr,
            "ShrincsWallet (impl)",
            keccak256(abi.encodePacked("QUIP:ShrincsWallet:V1.1:", SHRINCSParams.PROFILE_ID))
        );
        _predict(
            deployerAddr,
            "ShrincsPaymaster (impl)",
            keccak256(abi.encodePacked("QUIP:ShrincsPaymaster:Impl:V1.1:", SHRINCSParams.PROFILE_ID))
        );
        _predict(deployerAddr, "ShrincsPaymaster (proxy)", keccak256("QUIP:ShrincsPaymaster:Proxy:V1.1"));
        // Not deployed by this repo — the canonical hashsigs-solidity CREATE3
        // verifier the Shrincs impls pin (see DeployShrincsBase).
        console.log("SHRINCS256sKeccak (pinned):", 0xb76f5acfa4f1e993b36C9c72eD7514eC2c80F00A);
    }

    function _predict(address deployer, string memory name, bytes32 salt) internal pure {
        address predicted = CREATE3.predictDeterministicAddress(salt, deployer);
        console.log(string.concat(name, ":"), predicted);
    }
}
