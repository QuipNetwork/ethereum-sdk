// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {DeployerTest} from "../Deployer.t.sol";
import {Deployer} from "../../../contracts/Deployer.sol";
import {Vm} from "forge-std/Vm.sol";

contract Deployer_deploy is DeployerTest {
    function test_deploy_deploysContract() public {
        bytes memory bytecode = type(Deployer).creationCode;
        uint256 salt = 1;

        vm.prank(ADMIN);
        address deployed = deployer.deploy(bytecode, salt);

        assertTrue(deployed != address(0));
        assertTrue(deployed.code.length > 0);
    }

    function test_deploy_emitsDeployEvent() public {
        bytes memory bytecode = type(Deployer).creationCode;
        uint256 salt = 2;

        vm.prank(ADMIN);
        vm.recordLogs();
        deployer.deploy(bytecode, salt);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        assertEq(logs[0].topics[0], keccak256("Deploy(address)"));
    }

    function test_deploy_deterministicAddress() public {
        bytes memory bytecode = type(Deployer).creationCode;
        uint256 salt = 3;

        vm.prank(ADMIN);
        address deployed1 = deployer.deploy(bytecode, salt);

        // Deploy a second deployer and deploy with same salt
        Deployer deployer2 = new Deployer();
        address deployed2 = deployer2.deploy(bytecode, salt);

        // Different deployer addresses should give different CREATE2 addresses
        assertTrue(deployed1 != deployed2);
    }

    function test_deploy_revertsWhen_create2Fails() public {
        bytes memory bytecode = type(Deployer).creationCode;
        uint256 salt = 4;

        // Deploy once
        vm.prank(ADMIN);
        deployer.deploy(bytecode, salt);

        // Try to deploy again with same salt — CREATE2 collision
        vm.prank(ADMIN);
        vm.expectRevert();
        deployer.deploy(bytecode, salt);
    }
}
