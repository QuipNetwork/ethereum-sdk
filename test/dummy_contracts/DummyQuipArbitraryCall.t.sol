// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipArbitraryCall} from "../../contracts/dummy_contracts/DummyQuipArbitraryCall.sol";

contract Pong {
    uint256 public last;
    event Bonk(address from, uint256 value, uint256 arg);
    error PongRevert();

    function bonk(uint256 x) external payable returns (uint256) {
        last = x + msg.value;
        emit Bonk(msg.sender, msg.value, x);
        return last;
    }

    function alwaysReverts() external pure {
        revert PongRevert();
    }
}

contract DummyQuipArbitraryCallTest is Test {
    DummyQuipArbitraryCall internal arb;
    Pong internal pong;

    address internal alice = address(0xA11CE);

    function setUp() public {
        arb = new DummyQuipArbitraryCall();
        pong = new Pong();
    }

    function testRecordsPlainNativeReceive() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = address(arb).call{value: 0.3 ether}("");
        assertTrue(ok);

        assertEq(arb.callsCount(), 1);
        (address caller, uint256 value, bytes memory data) = arb.lastCall();
        assertEq(caller, alice);
        assertEq(value, 0.3 ether);
        assertEq(data.length, 0);
        assertEq(address(arb).balance, 0.3 ether);
    }

    function testRecordsFallbackWithData() public {
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        (bool ok,) = address(arb).call{value: 0.1 ether}(hex"deadbeef");
        assertTrue(ok);

        (address caller, uint256 value, bytes memory data) = arb.lastCall();
        assertEq(caller, alice);
        assertEq(value, 0.1 ether);
        assertEq(data, hex"deadbeef");
    }

    function testExecuteForwardsValueAndDataAndReturns() public {
        vm.deal(alice, 1 ether);

        bytes memory cd = abi.encodeWithSelector(Pong.bonk.selector, uint256(7));

        vm.prank(alice);
        bytes memory ret = arb.execute{value: 0.05 ether}(address(pong), cd);

        uint256 returned = abi.decode(ret, (uint256));
        assertEq(returned, 7 + 0.05 ether);
        assertEq(pong.last(), 7 + 0.05 ether);
        assertEq(address(pong).balance, 0.05 ether);
        assertEq(address(arb).balance, 0);
    }

    function testExecuteBubblesUpRevert() public {
        bytes memory cd = abi.encodeWithSelector(Pong.alwaysReverts.selector);
        bytes memory expected = abi.encodeWithSelector(Pong.PongRevert.selector);

        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipArbitraryCall.DummyQuipCallReverted.selector, address(pong), expected)
        );
        arb.execute(address(pong), cd);
    }

    function testGetCallByIndex() public {
        vm.deal(alice, 1 ether);

        vm.prank(alice);
        (bool ok1,) = address(arb).call{value: 0.01 ether}("");
        assertTrue(ok1);

        vm.prank(alice);
        (bool ok2,) = address(arb).call{value: 0.02 ether}(hex"01");
        assertTrue(ok2);

        assertEq(arb.callsCount(), 2);

        (address c0, uint256 v0, bytes memory d0) = arb.getCall(0);
        assertEq(c0, alice);
        assertEq(v0, 0.01 ether);
        assertEq(d0.length, 0);

        (address c1, uint256 v1, bytes memory d1) = arb.getCall(1);
        assertEq(c1, alice);
        assertEq(v1, 0.02 ether);
        assertEq(d1, hex"01");
    }
}
