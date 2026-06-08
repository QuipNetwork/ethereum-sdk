// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipArbitraryCall} from
    "../../contracts/dummy_contracts/DummyQuipArbitraryCall.sol";

contract DummyQuipArbitraryCallTest is Test {
    DummyQuipArbitraryCall internal target;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);

    function setUp() public {
        target = new DummyQuipArbitraryCall();
    }

    // -------------------------------------------------------------------------
    // Initial state.
    // -------------------------------------------------------------------------

    function testInitialState() public view {
        assertEq(target.pingCountOf(alice), 0);
        assertEq(target.pingCountOf(bob), 0);
        assertEq(target.pingCountOf(address(0)), 0);
    }

    // -------------------------------------------------------------------------
    // ping(): per-caller counter.
    // -------------------------------------------------------------------------

    function testPingBumpsCallerCounter() public {
        vm.prank(alice);
        target.ping();
        assertEq(target.pingCountOf(alice), 1);
        assertEq(target.pingCountOf(bob), 0);

        vm.prank(alice);
        target.ping();
        assertEq(target.pingCountOf(alice), 2);
    }

    function testPerCallerCountersAreIndependent() public {
        for (uint256 i = 0; i < 5; ++i) {
            vm.prank(alice);
            target.ping();
        }
        for (uint256 i = 0; i < 3; ++i) {
            vm.prank(bob);
            target.ping();
        }
        assertEq(target.pingCountOf(alice), 5);
        assertEq(target.pingCountOf(bob), 3);
        assertEq(target.pingCountOf(address(0xDEAD)), 0);
    }

    function testCallerIdentityIsMsgSenderNotTxOrigin() public {
        // Use a relay contract so `msg.sender` (relay) ≠ `tx.origin` (alice).
        // Mirrors the "EOA → smart wallet → ping" shape. The counter must
        // accumulate under the RELAY, not under `tx.origin`.
        PingRelay relay = new PingRelay(address(target));

        vm.prank(alice, alice); // tx.origin = alice, msg.sender = alice
        relay.relayPing();

        assertEq(target.pingCountOf(address(relay)), 1);
        assertEq(target.pingCountOf(alice), 0);
    }

    // -------------------------------------------------------------------------
    // alwaysRevert(): custom-error revert path.
    // -------------------------------------------------------------------------

    function testAlwaysRevertUsesCustomErrorSelector() public {
        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipArbitraryCall.AlwaysReverts.selector)
        );
        target.alwaysRevert();
    }

    function testAlwaysRevertDoesNotMutateState() public {
        vm.prank(alice);
        try target.alwaysRevert() {
            revert("alwaysRevert should have reverted");
        } catch {
            // Expected.
        }
        // No side effects — the per-caller counter must still read zero.
        assertEq(target.pingCountOf(alice), 0);
    }
}

/// @dev Minimal "smart wallet stand-in". Lets the regression test pin the
/// `msg.sender`-vs-`tx.origin` invariant: alice prank-calls the relay, relay
/// calls the dummy, so the dummy sees `msg.sender == relay` while
/// `tx.origin == alice` — the same shape as "EOA → QuipWallet → ping".
contract PingRelay {
    DummyQuipArbitraryCall internal immutable TARGET;

    constructor(address target_) {
        TARGET = DummyQuipArbitraryCall(target_);
    }

    function relayPing() external {
        TARGET.ping();
    }
}
