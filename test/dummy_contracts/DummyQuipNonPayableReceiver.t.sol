// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipNonPayableReceiver} from "../../contracts/dummy_contracts/DummyQuipNonPayableReceiver.sol";

contract DummyQuipNonPayableReceiverTest is Test {
    DummyQuipNonPayableReceiver internal receiver;

    function setUp() public {
        receiver = new DummyQuipNonPayableReceiver();
    }

    function testPing() public {
        vm.expectEmit(true, false, false, false);
        emit DummyQuipNonPayableReceiver.DummyQuipPing(address(this));
        receiver.ping();
    }

    function testNativeTransferFails() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(receiver).call{value: 1 wei}("");
        assertFalse(ok);
    }
}
