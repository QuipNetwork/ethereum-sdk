// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipCreate3Factory} from "../../contracts/dummy_contracts/DummyQuipCreate3Factory.sol";
import {DummyQuipPaymentReceiver} from "../../contracts/dummy_contracts/DummyQuipPaymentReceiver.sol";

contract DummyQuipCreate3FactoryTest is Test {
    DummyQuipCreate3Factory internal factory;

    function setUp() public {
        factory = new DummyQuipCreate3Factory();
    }

    function testPredictAndDeploy() public {
        bytes32 salt = keccak256(bytes("quip.dummy.DummyQuipPaymentReceiver.v1"));
        bytes memory creationCode = abi.encodePacked(
            type(DummyQuipPaymentReceiver).creationCode, abi.encode(address(this))
        );

        address predicted = factory.getDeployed(salt);
        address deployed = factory.deploy(salt, creationCode, 0);

        assertEq(deployed, predicted);
        assertGt(deployed.code.length, 0);
    }

    function testCannotReuseSalt() public {
        bytes32 salt = keccak256(bytes("quip.dummy.DummyQuipPaymentReceiver.v1"));
        bytes memory creationCode = abi.encodePacked(
            type(DummyQuipPaymentReceiver).creationCode, abi.encode(address(this))
        );

        factory.deploy(salt, creationCode, 0);

        address predicted = factory.getDeployed(salt);
        vm.expectRevert(abi.encodeWithSelector(DummyQuipCreate3Factory.DummyQuipAlreadyDeployed.selector, predicted));
        factory.deploy(salt, creationCode, 0);
    }

    function testGetProxyMatchesPrediction() public view {
        bytes32 salt = keccak256("proxy-salt");
        address proxy = factory.getProxy(salt);
        assertTrue(proxy != address(0));
        assertEq(factory.getDeployed(salt), address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01"))))));
    }

    function testIncorrectValueReverts() public {
        bytes32 salt = keccak256("value-salt");
        bytes memory creationCode = abi.encodePacked(
            type(DummyQuipPaymentReceiver).creationCode, abi.encode(address(this))
        );

        vm.expectRevert(abi.encodeWithSelector(DummyQuipCreate3Factory.DummyQuipIncorrectValue.selector, 1, 0));
        factory.deploy{value: 1}(salt, creationCode, 0);
    }
}
