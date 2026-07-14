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
        PackedUserOperation memory op = _checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 0, 1);

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
        PackedUserOperation memory op = _checkedSponsoredOp(CALL_TARGET, 0, hex"1234", 0, 1);

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

    /// @dev Fee decrease between signing and landing: the op lands and the wallet is charged the
    ///      LOWER live fee (the `<=` cap semantics; the old digest-bound design would have
    ///      invalidated the signature instead).
    function test_e2e_feeDecreaseLandsChargingLiveFee() public {
        factory.setExecuteFee(0.01 ether);
        SponsoredOpParams memory p = _defaultOpParams(RECIPIENT, 0.1 ether, "", 0, 1);
        p.maxFee = 0.01 ether;
        PackedUserOperation memory op = _buildSponsoredOp(p);
        _assertLiveHash(op);

        factory.setExecuteFee(0.002 ether); // fee lowered after the op was signed
        uint256 factoryBefore = address(factory).balance;
        uint256 recipientBefore = RECIPIENT.balance;

        _handle(op);

        assertEq(RECIPIENT.balance, recipientBefore + 0.1 ether, "transfer landed");
        assertEq(address(factory).balance - factoryBefore, 0.002 ether, "LIVE fee charged, not the ceiling");
        assertTrue(wallet.isStatefulLeafUsed(1), "wallet leaf consumed");
    }

    /// @dev Fee raised past the signed ceiling AFTER signing: validation passes (it reads no fee
    ///      — ERC-7562), so the op is included and the EXECUTION phase reverts on the cap. The
    ///      leaf and action nonce were consumed during validation and stay consumed — the
    ///      documented N-3a property of validation-phase stateful-signature consumption
    ///      (ERC7562_COMPLIANCE.md); the execution effect itself does not happen.
    function test_e2e_feeIncreasePastCap_executionRevertsLeafBurned() public {
        PackedUserOperation memory op = _checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 0, 1); // maxFee 0
        factory.setExecuteFee(0.01 ether); // raised past the signed ceiling after signing

        uint256 recipientBefore = RECIPIENT.balance;
        uint256 factoryBefore = address(factory).balance;
        assertEq(wallet.actionNonce(), 0, "pre: nonce untouched");

        _handle(op); // does NOT revert: execution-phase failures are absorbed by the EntryPoint

        assertEq(RECIPIENT.balance, recipientBefore, "execution effect did not happen");
        assertEq(address(factory).balance, factoryBefore, "no fee collected");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf consumed during validation stays consumed");
        assertEq(wallet.actionNonce(), 1, "nonce advanced during validation stays advanced");
    }

    function test_e2e_emitsSponsorshipEvents() public {
        PackedUserOperation memory op = _checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 0, 1);

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
