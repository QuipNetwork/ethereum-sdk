// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {DeployerTest} from "../Deployer.t.sol";
import {Deployer} from "../../../contracts/Deployer.sol";

contract Deployer_predictAddress is DeployerTest {
    function test_predictAddress_matchesDeployedAddress() public {
        bytes32 salt = keccak256("test-salt");
        address predicted = deployer.predictAddress(salt);

        bytes memory bytecode = type(Deployer).creationCode;
        vm.prank(ADMIN);
        address deployed = deployer.deploy(bytecode, salt);

        assertEq(predicted, deployed);
    }

    function test_predictAddress_returnsDeterministicResult() public view {
        bytes32 salt = keccak256("deterministic-salt");
        address first = deployer.predictAddress(salt);
        address second = deployer.predictAddress(salt);
        assertEq(first, second);
    }

    function test_predictAddress_returnsDifferentAddressForDifferentSalt() public view {
        bytes32 salt1 = keccak256("salt-1");
        bytes32 salt2 = keccak256("salt-2");
        assertTrue(deployer.predictAddress(salt1) != deployer.predictAddress(salt2));
    }
}
