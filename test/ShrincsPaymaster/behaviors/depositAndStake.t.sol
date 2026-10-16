// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IEntryPointStake} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the EntryPoint deposit/stake forwarders. The EntryPoint is mocked via
///      `vm.mockCall` (no real EntryPoint deployment needed).
contract ShrincsPaymaster_depositAndStake is ShrincsPaymasterTest {
    function setUp() public override {
        super.setUp();
        // Make every EntryPoint stake/deposit call a no-op success by default.
        vm.mockCall(
            ENTRY_POINT,
            abi.encodeWithSelector(IEntryPointStake.depositTo.selector),
            ""
        );
        vm.mockCall(
            ENTRY_POINT,
            abi.encodeWithSelector(IEntryPointStake.withdrawTo.selector),
            ""
        );
        vm.mockCall(
            ENTRY_POINT,
            abi.encodeWithSelector(IEntryPointStake.addStake.selector),
            ""
        );
        vm.mockCall(
            ENTRY_POINT,
            abi.encodeWithSelector(IEntryPointStake.unlockStake.selector),
            ""
        );
        vm.mockCall(
            ENTRY_POINT,
            abi.encodeWithSelector(IEntryPointStake.withdrawStake.selector),
            ""
        );
    }

    function test_deposit_forwardsValueToEntryPoint() public {
        vm.expectCall(
            ENTRY_POINT,
            1 ether,
            abi.encodeWithSelector(
                IEntryPointStake.depositTo.selector,
                PAYMASTER
            )
        );
        vm.deal(address(this), 1 ether);
        paymaster.deposit{value: 1 ether}();
    }

    function test_getDeposit_returnsEntryPointBalance() public {
        vm.mockCall(
            ENTRY_POINT,
            abi.encodeWithSelector(
                IEntryPointStake.balanceOf.selector,
                PAYMASTER
            ),
            abi.encode(uint256(42 ether))
        );
        assertEq(paymaster.getDeposit(), 42 ether);
    }

    function test_withdrawTo_forwards() public {
        address payable to = payable(makeAddr("to"));
        vm.expectCall(
            ENTRY_POINT,
            abi.encodeWithSelector(
                IEntryPointStake.withdrawTo.selector,
                to,
                3 ether
            )
        );
        vm.prank(OWNER);
        paymaster.withdrawTo(to, 3 ether);
    }

    function test_addStake_forwards() public {
        vm.deal(OWNER, 5 ether);
        vm.expectCall(
            ENTRY_POINT,
            5 ether,
            abi.encodeWithSelector(
                IEntryPointStake.addStake.selector,
                uint32(86400)
            )
        );
        vm.prank(OWNER);
        paymaster.addStake{value: 5 ether}(86400);
    }

    function test_unlockStake_forwards() public {
        vm.expectCall(
            ENTRY_POINT,
            abi.encodeWithSelector(IEntryPointStake.unlockStake.selector)
        );
        vm.prank(OWNER);
        paymaster.unlockStake();
    }

    function test_withdrawStake_forwards() public {
        address payable to = payable(makeAddr("to"));
        vm.expectCall(
            ENTRY_POINT,
            abi.encodeWithSelector(IEntryPointStake.withdrawStake.selector, to)
        );
        vm.prank(OWNER);
        paymaster.withdrawStake(to);
    }

    /* access control — all but deposit are onlyOwner */

    function test_withdrawTo_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.withdrawTo(payable(makeAddr("to")), 1);
    }

    function test_addStake_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.addStake(1);
    }

    function test_unlockStake_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.unlockStake();
    }

    function test_withdrawStake_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.withdrawStake(payable(makeAddr("to")));
    }
}
