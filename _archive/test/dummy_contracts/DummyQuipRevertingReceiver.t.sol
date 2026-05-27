// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipRevertingReceiver} from "../../contracts/dummy_contracts/DummyQuipRevertingReceiver.sol";

contract DummyQuipRevertingReceiverTest is Test {
    DummyQuipRevertingReceiver internal receiver;

    function setUp() public {
        receiver = new DummyQuipRevertingReceiver();
    }

    function testReceiveReverts() public {
        vm.deal(address(this), 1 ether);
        vm.expectRevert(DummyQuipRevertingReceiver.DummyQuipForcedRevert.selector);
        payable(address(receiver)).transfer(1 wei);
    }

    function testFallbackReverts() public {
        vm.deal(address(this), 1 ether);
        vm.expectRevert(DummyQuipRevertingReceiver.DummyQuipForcedRevert.selector);
        payable(address(receiver)).call{value: 1 wei}(hex"01");
    }

    function testAlwaysRevert() public {
        vm.expectRevert(DummyQuipRevertingReceiver.DummyQuipForcedRevert.selector);
        receiver.alwaysRevert();
    }
}
