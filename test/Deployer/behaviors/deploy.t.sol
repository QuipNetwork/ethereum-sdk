// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {DeployerTest} from "../Deployer.t.sol";
import {Deployer} from "../../../contracts/Deployer.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract Deployer_deploy is DeployerTest {
    function test_deploy_deploysContract() public {
        bytes memory bytecode = type(Deployer).creationCode;
        bytes32 salt = bytes32(uint256(1));

        vm.prank(ADMIN);
        address deployed = deployer.deploy(bytecode, salt);

        assertTrue(deployed != address(0));
        assertTrue(deployed.code.length > 0);
    }

    function test_deploy_emitsDeployEvent() public {
        bytes memory bytecode = type(Deployer).creationCode;
        bytes32 salt = bytes32(uint256(2));

        vm.prank(ADMIN);
        vm.recordLogs();
        deployer.deploy(bytecode, salt);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], keccak256("Deploy(address)"));
    }

    function test_deploy_deterministicAddress() public {
        bytes memory bytecode = type(Deployer).creationCode;
        bytes32 salt = bytes32(uint256(3));

        vm.prank(ADMIN);
        address deployed1 = deployer.deploy(bytecode, salt);

        // Deploy a second deployer and deploy with same salt
        Deployer deployer2 = new Deployer();
        address deployed2 = deployer2.deploy(bytecode, salt);

        // Different deployer addresses should give different CREATE3 addresses
        assertTrue(deployed1 != deployed2);
    }

    function test_deploy_revertsWhen_deploymentFails() public {
        bytes memory bytecode = type(Deployer).creationCode;
        bytes32 salt = bytes32(uint256(4));

        // Deploy once
        vm.prank(ADMIN);
        deployer.deploy(bytecode, salt);

        // Try to deploy again with same salt — CREATE3 collision
        vm.prank(ADMIN);
        vm.expectRevert();
        deployer.deploy(bytecode, salt);
    }
}
