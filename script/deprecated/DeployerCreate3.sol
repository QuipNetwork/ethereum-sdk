// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {console} from "forge-std-1.14.0/Script.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {Deployer} from "../../contracts/deprecated/Deployer.sol";
import {DeployHelpers} from "../DeployHelpers.sol";

/**
 * @title DeployerCreate3
 * @dev CREATE3-via-`Deployer` deploy primitive for the sunset WOTS+ family. The
 *      live system deploys straight through CreateX with sender-guarded salts
 *      (`script/CreateXHelpers.sol`); this Deployer hop remains ONLY so the
 *      deprecated family's deploy flow — and its already-deployed, Deployer-derived
 *      canonical addresses (Base Sepolia `0xA1A3990E…` era) — keep working.
 */
abstract contract DeployerCreate3 is DeployHelpers {
    /// Deploy `bytecode` at the deterministic `(deployer, salt)` CREATE3 address,
    /// skipping if already present. Reverts on an unexpected address.
    function _create3(
        Deployer deployer,
        uint256 privateKey,
        bytes memory bytecode,
        bytes32 salt,
        string memory name
    ) internal returns (address deployed) {
        address expected = CREATE3.predictDeterministicAddress(salt, address(deployer));
        if (expected.code.length > 0) {
            console.log(string.concat("  - ", name, " already at"), expected);
            return expected;
        }
        vm.startBroadcast(privateKey);
        deployed = deployer.deploy(bytecode, salt);
        vm.stopBroadcast();
        require(deployed == expected, string.concat(name, ": CREATE3 address mismatch"));
        console.log(string.concat("  - ", name, " deployed at"), deployed);
    }
}
