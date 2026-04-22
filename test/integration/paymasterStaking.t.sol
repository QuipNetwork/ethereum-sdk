// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IntegrationBase, IEntryPointStake} from "./IntegrationBase.t.sol";

/// @title Paymaster Staking Integration Test
/// @dev Fork test against the real EntryPoint v0.7 on Base Sepolia.
///      Verifies deposit, stake, and withdrawal operations succeed against
///      the deployed singleton.
contract Integration_paymasterStaking is IntegrationBase {
    function setUp() public override {
        super.setUp();
        _deployPaymaster();
    }

    /// @dev Verify deposit to EntryPoint succeeds and updates reported balance.
    function test_integration_deposit() public {
        uint256 depositAmount = 1 ether;
        vm.deal(address(paymaster), depositAmount);

        uint256 balBefore = paymaster.getDeposit();
        paymaster.deposit{value: depositAmount}();
        uint256 balAfter = paymaster.getDeposit();

        assertEq(balAfter, balBefore + depositAmount);
    }

    /// @dev Verify addStake succeeds on the real EntryPoint.
    function test_integration_addStake() public {
        vm.prank(ADMIN);
        paymaster.addStake{value: 1 ether}(60);
    }

    /// @dev Verify unlockStake succeeds after staking.
    function test_integration_unlockStake() public {
        vm.startPrank(ADMIN);
        paymaster.addStake{value: 1 ether}(1);
        paymaster.unlockStake();
        vm.stopPrank();
    }

    /// @dev Full stake lifecycle: stake → unlock → wait → withdraw.
    function test_integration_withdrawStake() public {
        vm.startPrank(ADMIN);
        paymaster.addStake{value: 1 ether}(1);
        paymaster.unlockStake();
        vm.stopPrank();

        vm.warp(block.timestamp + 2);

        uint256 adminBalBefore = ADMIN.balance;
        vm.prank(ADMIN);
        paymaster.withdrawStake(payable(ADMIN));

        assertGt(ADMIN.balance, adminBalBefore);
    }

    /// @dev Verify withdrawTo retrieves deposited funds from EntryPoint.
    function test_integration_withdrawTo() public {
        uint256 depositAmount = 2 ether;
        vm.deal(address(paymaster), depositAmount);
        paymaster.deposit{value: depositAmount}();

        uint256 withdrawAmount = 1 ether;
        uint256 adminBalBefore = ADMIN.balance;

        vm.prank(ADMIN);
        paymaster.withdrawTo(payable(ADMIN), withdrawAmount);

        assertEq(ADMIN.balance, adminBalBefore + withdrawAmount);
        assertEq(paymaster.getDeposit(), depositAmount - withdrawAmount);
    }

    /// @dev Verify getDeposit matches the EntryPoint's balanceOf for the paymaster.
    function test_integration_getDeposit_matchesEntryPoint() public {
        vm.deal(address(paymaster), 3 ether);
        paymaster.deposit{value: 3 ether}();

        uint256 reported = paymaster.getDeposit();
        uint256 actual = IEntryPointStake(ENTRY_POINT).balanceOf(
            address(paymaster)
        );

        assertEq(reported, actual);
    }
}
