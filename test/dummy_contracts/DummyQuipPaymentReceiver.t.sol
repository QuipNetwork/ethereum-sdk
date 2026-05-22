// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipOwned} from "../../contracts/dummy_contracts/DummyQuipOwned.sol";
import {DummyQuipPaymentReceiver} from "../../contracts/dummy_contracts/DummyQuipPaymentReceiver.sol";

contract DummyQuipPaymentReceiverTest is Test {
    DummyQuipPaymentReceiver internal receiver;
    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        receiver = new DummyQuipPaymentReceiver(address(this));
    }

    function testReceiveAcceptsNative() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = address(receiver).call{value: 0.1 ether}("");
        assertTrue(ok);
        assertEq(address(receiver).balance, 0.1 ether);
    }

    function testFallbackAcceptsNativeWithData() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = address(receiver).call{value: 0.2 ether}(hex"deadbeef");
        assertTrue(ok);
        assertEq(address(receiver).balance, 0.2 ether);
    }

    function testPayEmitsReferencePayment() public {
        vm.deal(alice, 1 ether);
        bytes32 ref = keccak256("ref-1");

        vm.prank(alice);
        vm.expectEmit(true, false, true, true);
        emit DummyQuipPaymentReceiver.DummyQuipReferencePayment(alice, 0.05 ether, ref);
        receiver.pay{value: 0.05 ether}(ref);

        assertEq(address(receiver).balance, 0.05 ether);
    }

    function testWithdrawNativeOnlyOwner() public {
        vm.deal(address(receiver), 1 ether);

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(DummyQuipOwned.DummyQuipNotOwner.selector, alice));
        receiver.withdrawNative(payable(bob), 0.25 ether);

        receiver.withdrawNative(payable(bob), 0.25 ether);
        assertEq(bob.balance, 0.25 ether);
        assertEq(address(receiver).balance, 0.75 ether);
    }
}
