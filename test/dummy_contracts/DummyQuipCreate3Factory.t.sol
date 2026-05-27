// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipCreate3Factory} from "../../contracts/dummy_contracts/DummyQuipCreate3Factory.sol";

/// @dev Trivial contract used purely as a CREATE3 deploy target in factory tests.
contract Create3DeployTarget {
    uint256 public value;

    constructor(uint256 initial) {
        value = initial;
    }
}

contract DummyQuipCreate3FactoryTest is Test {
    DummyQuipCreate3Factory internal factory;

    function setUp() public {
        factory = new DummyQuipCreate3Factory();
    }

    function testPredictAndDeploy() public {
        bytes32 salt = keccak256(bytes("quip.dummy.test.deploy.v1"));
        bytes memory creationCode = abi.encodePacked(
            type(Create3DeployTarget).creationCode, abi.encode(uint256(42))
        );

        address predicted = factory.getDeployed(salt);
        address deployed = factory.deploy(salt, creationCode);

        assertEq(deployed, predicted);
        assertGt(deployed.code.length, 0);
        assertEq(Create3DeployTarget(deployed).value(), 42);
    }

    function testCannotReuseSalt() public {
        bytes32 salt = keccak256(bytes("quip.dummy.test.reuse.v1"));
        bytes memory creationCode = abi.encodePacked(
            type(Create3DeployTarget).creationCode, abi.encode(uint256(7))
        );

        factory.deploy(salt, creationCode);

        address predicted = factory.getDeployed(salt);
        bytes4 sel = DummyQuipCreate3Factory.DummyQuipAlreadyDeployed.selector;
        vm.expectRevert(abi.encodeWithSelector(sel, predicted));
        factory.deploy(salt, creationCode);
    }

    function testGetProxyMatchesPrediction() public view {
        bytes32 salt = keccak256("proxy-salt");
        address proxy = factory.getProxy(salt);
        assertTrue(proxy != address(0));
        bytes32 hashed = keccak256(abi.encodePacked(hex"d694", proxy, hex"01"));
        address expected = address(uint160(uint256(hashed)));
        assertEq(factory.getDeployed(salt), expected);
    }
}
