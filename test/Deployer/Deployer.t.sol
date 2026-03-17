// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {Test} from "forge-std-1.14.0/Test.sol";
import {Deployer} from "../../contracts/Deployer.sol";

contract DeployerTest is Test {
    Deployer public deployer;

    address public ADMIN = makeAddr("admin");

    function setUp() public virtual {
        vm.prank(ADMIN);
        deployer = new Deployer();
    }

    function test_setUp() public view {
        assertTrue(address(deployer) != address(0));
    }
}
