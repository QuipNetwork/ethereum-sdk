// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IntegrationBase, IEntryPointStake} from "./IntegrationBase.t.sol";

/// @dev Subset of the v0.7 EntryPoint surface that exposes per-account stake
///      state. Not in OpenZeppelin's `IEntryPointStake`, so we declare it
///      locally to read back the canonical state transitions on the fork.
interface IEntryPointDepositInfo {
    struct DepositInfo {
        uint256 deposit;
        bool staked;
        uint112 stake;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    function getDepositInfo(
        address account
    ) external view returns (DepositInfo memory info);
}

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

    /// @dev Top-up with `unstakeDelaySec` lower than the current value must
    ///      revert. Real EntryPoint v0.7 enforces
    ///      `_unstakeDelaySec >= info.unstakeDelaySec` with a string-revert
    ///      ("cannot decrease unstake time"). Our local mock at
    ///      `depositStakeLifecycle.t.sol` does NOT enforce this, so without
    ///      this fork-side test a refactor that relies on the mock's looser
    ///      semantics would pass tests but break in production.
    function test_integration_addStake_revertsWhen_lowerDelay() public {
        vm.startPrank(ADMIN);
        paymaster.addStake{value: 1 ether}(120);

        vm.expectRevert(bytes("cannot decrease unstake time"));
        paymaster.addStake{value: 0.5 ether}(60);
        vm.stopPrank();
    }

    /// @dev Top-up with a HIGHER `unstakeDelaySec` extends the window and
    ///      stacks the stake amount. Documents the standard v0.7 semantics:
    ///      the delay is monotone-increasing per account and the stake
    ///      accumulates across calls.
    function test_integration_addStake_succeedsWhen_higherDelay() public {
        vm.startPrank(ADMIN);
        paymaster.addStake{value: 1 ether}(60);
        paymaster.addStake{value: 0.5 ether}(120);
        vm.stopPrank();

        IEntryPointDepositInfo.DepositInfo memory info = IEntryPointDepositInfo(
            ENTRY_POINT
        ).getDepositInfo(address(paymaster));
        assertTrue(info.staked, "must be staked");
        assertEq(info.stake, 1.5 ether, "stake must accumulate");
        assertEq(info.unstakeDelaySec, 120, "delay must extend");
        assertEq(info.withdrawTime, 0, "must remain locked");
    }

    /// @dev Top-up with the SAME delay accumulates the stake without changing
    ///      the delay. Companion to the higher-delay test; covers the third
    ///      branch the mock's loose semantics conflate with the lower-delay
    ///      case.
    function test_integration_addStake_succeedsWhen_sameDelay() public {
        vm.startPrank(ADMIN);
        paymaster.addStake{value: 1 ether}(60);
        paymaster.addStake{value: 0.25 ether}(60);
        vm.stopPrank();

        IEntryPointDepositInfo.DepositInfo memory info = IEntryPointDepositInfo(
            ENTRY_POINT
        ).getDepositInfo(address(paymaster));
        assertEq(info.stake, 1.25 ether);
        assertEq(info.unstakeDelaySec, 60);
        assertEq(info.withdrawTime, 0);
    }

    /// @dev `addStake` during an active unlock window CANCELS the unlock by
    ///      resetting `withdrawTime` to 0. A future `withdrawStake` must then
    ///      revert because the stake is re-locked. Without this regression
    ///      test, an operator who tops up mid-unlock would silently lose
    ///      their unstake countdown.
    function test_integration_addStake_topUp_cancelsActiveUnlock() public {
        vm.startPrank(ADMIN);
        paymaster.addStake{value: 1 ether}(60);
        paymaster.unlockStake();

        IEntryPointDepositInfo.DepositInfo memory beforeTopUp = (
            IEntryPointDepositInfo(ENTRY_POINT).getDepositInfo(
                address(paymaster)
            )
        );
        assertGt(beforeTopUp.withdrawTime, 0, "unlock must arm withdrawTime");

        // Top up with the same delay: re-locks per v0.7 semantics.
        paymaster.addStake{value: 0.1 ether}(60);

        IEntryPointDepositInfo.DepositInfo memory afterTopUp = (
            IEntryPointDepositInfo(ENTRY_POINT).getDepositInfo(
                address(paymaster)
            )
        );
        assertEq(afterTopUp.withdrawTime, 0, "top-up must reset withdrawTime");
        assertTrue(afterTopUp.staked, "must remain staked");

        // Warp past the original unlock target — withdrawStake must still
        // revert because the top-up cancelled the unlock.
        vm.warp(block.timestamp + 120);
        vm.expectRevert(bytes("must call unlockStake() first"));
        paymaster.withdrawStake(payable(ADMIN));
        vm.stopPrank();
    }

    /// @dev After a full stake → unlock → wait → withdraw cycle, calling
    ///      `addStake` again must succeed and start a fresh stake — including
    ///      the freedom to choose a NEW (even lower) `unstakeDelaySec`,
    ///      because `withdrawStake` resets `info.unstakeDelaySec` to 0 in
    ///      v0.7. Documents that re-entry into the staking lifecycle is
    ///      unconstrained by prior delays.
    function test_integration_reStake_afterWithdrawStake_succeedsWithFreshDelay()
        public
    {
        vm.startPrank(ADMIN);
        paymaster.addStake{value: 1 ether}(120);
        paymaster.unlockStake();
        vm.stopPrank();

        vm.warp(block.timestamp + 121);

        vm.prank(ADMIN);
        paymaster.withdrawStake(payable(ADMIN));

        IEntryPointDepositInfo.DepositInfo memory afterDrain = (
            IEntryPointDepositInfo(ENTRY_POINT).getDepositInfo(
                address(paymaster)
            )
        );
        assertFalse(afterDrain.staked, "withdraw must clear staked");
        assertEq(afterDrain.stake, 0);
        assertEq(afterDrain.unstakeDelaySec, 0);
        assertEq(afterDrain.withdrawTime, 0);

        // Re-stake with a delay LOWER than the previous one — only allowed
        // because the previous lifecycle was fully drained. Picks 60s vs the
        // earlier 120s to make the regression target unambiguous.
        vm.prank(ADMIN);
        paymaster.addStake{value: 0.5 ether}(60);

        IEntryPointDepositInfo.DepositInfo memory afterRestake = (
            IEntryPointDepositInfo(ENTRY_POINT).getDepositInfo(
                address(paymaster)
            )
        );
        assertTrue(afterRestake.staked, "must be re-staked");
        assertEq(afterRestake.stake, 0.5 ether);
        assertEq(afterRestake.unstakeDelaySec, 60);
        assertEq(afterRestake.withdrawTime, 0);
    }
}
