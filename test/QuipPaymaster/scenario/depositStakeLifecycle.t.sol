// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

/// @dev Minimal in-memory EntryPoint that mirrors the surface the paymaster
///      exercises: `depositTo`, `withdrawTo`, `addStake`, `unlockStake`,
///      `withdrawStake`, `balanceOf`. Tracks per-account deposits + stake
///      state so the scenario can assert balance flow end-to-end without a
///      fork of the v0.7 singleton.
contract MockEntryPointForLifecycle {
    mapping(address => uint256) public deposits;

    struct StakeInfo {
        uint256 amount;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    mapping(address => StakeInfo) public stakeInfo;

    function depositTo(address account) external payable {
        deposits[account] += msg.value;
    }

    function withdrawTo(address payable to, uint256 amount) external {
        require(deposits[msg.sender] >= amount, "insufficient deposit");
        deposits[msg.sender] -= amount;
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function addStake(uint32 unstakeDelaySec) external payable {
        StakeInfo storage s = stakeInfo[msg.sender];
        s.amount += msg.value;
        s.unstakeDelaySec = unstakeDelaySec;
        s.withdrawTime = 0; // Fresh deposits re-lock the stake.
    }

    function unlockStake() external {
        StakeInfo storage s = stakeInfo[msg.sender];
        require(s.amount > 0, "no stake");
        s.withdrawTime = uint48(block.timestamp + s.unstakeDelaySec);
    }

    function withdrawStake(address payable to) external {
        StakeInfo storage s = stakeInfo[msg.sender];
        require(s.amount > 0, "no stake");
        require(s.withdrawTime != 0, "not unlocked");
        require(block.timestamp >= s.withdrawTime, "not ready");
        uint256 amount = s.amount;
        delete stakeInfo[msg.sender];
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "stake transfer failed");
    }

    function balanceOf(address account) external view returns (uint256) {
        return deposits[account];
    }

    receive() external payable {}
}

/// @title QuipPaymaster Deposit + Stake Lifecycle Scenario
/// @dev Exercises the full EntryPoint deposit and stake management surface end
///      to end: deposit → getDeposit → owner withdraws some back → restake
///      into the EntryPoint's reputation system → unlockStake → advance past
///      the unstake delay → withdrawStake → verify final balances.
///
///      Uses an in-memory mock etched at the canonical EntryPoint singleton
///      address so the paymaster's hardcoded `ENTRY_POINT` constant resolves
///      to logic that actually tracks state across calls.
contract QuipPaymaster_depositStakeLifecycle is QuipPaymasterTest {
    address payable internal RECIPIENT;
    address payable internal STAKE_RECIPIENT;
    uint32 internal constant UNSTAKE_DELAY = 1 hours;

    function setUp() public override {
        super.setUp();

        // Etch a minimal mock EntryPoint at the singleton address the paymaster
        // hard-codes. The inherited setUp already pre-funded the paymaster to
        // 10 ether, but that was direct — mock deposits start at 0.
        MockEntryPointForLifecycle mock = new MockEntryPointForLifecycle();
        vm.etch(ENTRY_POINT, address(mock).code);

        RECIPIENT = payable(makeAddr("deposit-recipient"));
        STAKE_RECIPIENT = payable(makeAddr("stake-recipient"));

        // Wipe the direct funding the base setUp did; the lifecycle tests
        // assume the paymaster has no ambient balance (deposits go to the
        // EntryPoint, not the paymaster address itself).
        vm.deal(address(paymaster), 0);
    }

    function test_simulation_depositStakeLifecycle() public {
        uint256 depositAmount = 2 ether;
        uint256 withdrawBack = 0.5 ether;
        uint256 stakeAmount = 1.5 ether;

        // ── Step 1: Anyone can deposit on behalf of the paymaster ─────
        //   Note: `deposit()` has no access gate — this funds the paymaster's
        //   balance at the EntryPoint so it can sponsor UserOps.
        address relayer = makeAddr("relayer");
        vm.deal(relayer, depositAmount);
        vm.prank(relayer);
        paymaster.deposit{value: depositAmount}();

        assertEq(paymaster.getDeposit(), depositAmount);

        // ── Step 2: Owner withdraws part of the deposit back to RECIPIENT ──
        uint256 recipientBefore = RECIPIENT.balance;
        vm.prank(ADMIN);
        paymaster.withdrawTo(RECIPIENT, withdrawBack);

        assertEq(paymaster.getDeposit(), depositAmount - withdrawBack);
        assertEq(RECIPIENT.balance, recipientBefore + withdrawBack);

        // ── Step 3: Non-owner cannot withdraw ─────────────────────────
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.withdrawTo(RECIPIENT, 0.1 ether);
        // Deposit unchanged.
        assertEq(paymaster.getDeposit(), depositAmount - withdrawBack);

        // ── Step 4: Owner stakes ETH with the EntryPoint for reputation ──
        //   Stake is ACCOUNTED SEPARATELY from the deposit (different EntryPoint
        //   slot) — the deposit reading must not reflect the stake.
        vm.deal(ADMIN, stakeAmount);
        vm.prank(ADMIN);
        paymaster.addStake{value: stakeAmount}(UNSTAKE_DELAY);

        // Stake does not change deposit.
        assertEq(paymaster.getDeposit(), depositAmount - withdrawBack);

        // ── Step 5: Non-owner cannot initiate unstake ─────────────────
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.unlockStake();

        // ── Step 6: Owner unlocks the stake, starting the unstake delay ──
        vm.prank(ADMIN);
        paymaster.unlockStake();

        // ── Step 7: Withdrawing stake before the delay elapses reverts ──
        vm.prank(ADMIN);
        vm.expectRevert(bytes("not ready"));
        paymaster.withdrawStake(STAKE_RECIPIENT);

        // ── Step 8: Advance time past the unstake delay ───────────────
        vm.warp(block.timestamp + UNSTAKE_DELAY + 1);

        // ── Step 9: Non-owner still cannot withdraw the stake ─────────
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.withdrawStake(STAKE_RECIPIENT);

        // ── Step 10: Owner withdraws stake after delay ────────────────
        uint256 stakeRecipientBefore = STAKE_RECIPIENT.balance;
        vm.prank(ADMIN);
        paymaster.withdrawStake(STAKE_RECIPIENT);
        assertEq(STAKE_RECIPIENT.balance, stakeRecipientBefore + stakeAmount);

        // Deposit still independent of stake.
        assertEq(paymaster.getDeposit(), depositAmount - withdrawBack);

        // ── Step 11: Owner drains the remaining deposit ───────────────
        uint256 remaining = paymaster.getDeposit();
        vm.prank(ADMIN);
        paymaster.withdrawTo(RECIPIENT, remaining);
        assertEq(paymaster.getDeposit(), 0);
        assertEq(
            RECIPIENT.balance,
            recipientBefore + withdrawBack + remaining
        );
    }

    // Test deposit ergonomics: additional deposits stack cumulatively.
    function test_simulation_cumulativeDeposits() public {
        vm.deal(ADMIN, 3 ether);
        vm.startPrank(ADMIN);
        paymaster.deposit{value: 1 ether}();
        assertEq(paymaster.getDeposit(), 1 ether);
        paymaster.deposit{value: 1 ether}();
        assertEq(paymaster.getDeposit(), 2 ether);
        paymaster.deposit{value: 0.5 ether}();
        assertEq(paymaster.getDeposit(), 2.5 ether);
        vm.stopPrank();
    }

    // Test stake ergonomics: addStake without prior unlock extends the stake
    // and keeps it locked.
    function test_simulation_stakeTopUpStaysLocked() public {
        vm.deal(ADMIN, 3 ether);
        vm.startPrank(ADMIN);
        paymaster.addStake{value: 1 ether}(UNSTAKE_DELAY);
        paymaster.addStake{value: 0.5 ether}(UNSTAKE_DELAY);
        vm.stopPrank();

        // Stake still locked — withdrawStake must revert since we never unlocked.
        vm.prank(ADMIN);
        vm.expectRevert(bytes("not unlocked"));
        paymaster.withdrawStake(STAKE_RECIPIENT);
    }
}
