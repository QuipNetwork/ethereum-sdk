// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsE2EBase} from "./ShrincsE2EBase.t.sol";

/// @dev Happy-path e2e: the paymaster sponsors a wallet UserOp through the real EntryPoint. Proves
///      co-validation of both PQ signatures, real gas sponsorship (deposit accounting), the executed
///      effect, and that both anti-replay bitmaps advanced.
contract ShrincsE2E_sponsoredExecute is ShrincsE2EBase {
    function test_e2e_sponsoredEthTransfer() public {
        PackedUserOperation memory op = _op("sponsoredEthTransfer");

        uint256 pmDepositBefore = _deposit(PAYMASTER);
        uint256 walletDepositBefore = _deposit(WALLET);
        uint256 walletBalBefore = WALLET.balance;
        uint256 recipientBefore = RECIPIENT.balance;

        _handle(op);

        // Sponsorship: paymaster paid, wallet's own deposit untouched.
        assertLt(_deposit(PAYMASTER), pmDepositBefore, "paymaster paid gas");
        assertEq(
            _deposit(WALLET),
            walletDepositBefore,
            "wallet deposit untouched (paymaster paid)"
        );
        // Execution effect: wallet only out the transfer amount, recipient credited.
        assertEq(
            RECIPIENT.balance,
            recipientBefore + 0.1 ether,
            "recipient received 0.1 ETH"
        );
        assertEq(
            WALLET.balance,
            walletBalBefore - 0.1 ether,
            "wallet only out the transfer (no gas)"
        );
        // Both one-time leaves consumed.
        assertTrue(wallet.isStatefulLeafUsed(1), "wallet leaf 1 consumed");
        assertTrue(
            paymaster.isStatefulLeafUsed(1),
            "paymaster leaf 1 consumed"
        );
    }

    function test_e2e_sponsoredContractCall() public {
        PackedUserOperation memory op = _op("sponsoredContractCall");

        uint256 pmDepositBefore = _deposit(PAYMASTER);

        _handle(op);

        assertLt(_deposit(PAYMASTER), pmDepositBefore, "paymaster paid gas");
        assertEq(callTarget.callCount(), 1, "target invoked once");
        assertEq(callTarget.lastCaller(), WALLET, "wallet was the caller");
        assertEq(callTarget.lastValue(), 0, "no value forwarded");
        assertEq(callTarget.lastData(), hex"1234", "calldata forwarded");
        assertTrue(wallet.isStatefulLeafUsed(1), "wallet leaf consumed");
        assertTrue(paymaster.isStatefulLeafUsed(1), "paymaster leaf consumed");
    }

    function test_e2e_emitsSponsorshipEvents() public {
        PackedUserOperation memory op = _op("sponsoredEthTransfer");

        vm.recordLogs();
        _handle(op);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bool sponsorshipVerified;
        bool userOpSponsored;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                IShrincsPaymaster.SponsorshipVerified.selector
            ) sponsorshipVerified = true;
            if (logs[i].topics[0] == IShrincsPaymaster.UserOpSponsored.selector)
                userOpSponsored = true;
        }
        assertTrue(sponsorshipVerified, "SponsorshipVerified emitted");
        assertTrue(userOpSponsored, "UserOpSponsored (postOp) emitted");
    }
}
