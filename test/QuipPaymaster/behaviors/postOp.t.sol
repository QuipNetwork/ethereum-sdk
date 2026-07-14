// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../contracts/deprecated/interfaces/IQuipPaymaster.sol";
import {IPaymaster} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

contract QuipPaymaster_postOp is QuipPaymasterTest {
    function test_postOp_emitsUserOpSponsoredOnSuccess() public {
        bytes memory ctx = abi.encode(WALLET);
        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.UserOpSponsored(WALLET, IPaymaster.PostOpMode.opSucceeded, 21_000, 10 gwei);
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, 21_000, 10 gwei);
    }

    function test_postOp_emitsUserOpSponsoredOnOpReverted() public {
        bytes memory ctx = abi.encode(WALLET);
        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.UserOpSponsored(WALLET, IPaymaster.PostOpMode.opReverted, 21_000, 10 gwei);
        paymaster.postOp(IPaymaster.PostOpMode.opReverted, ctx, 21_000, 10 gwei);
    }

    // postOpReverted is the EntryPoint's re-entry path after a prior postOp
    // call reverted. We still emit so the audit trail covers the abnormal
    // case — that's exactly when an operator most wants a log.
    function test_postOp_emitsUserOpSponsoredOnPostOpReverted() public {
        bytes memory ctx = abi.encode(WALLET);
        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.UserOpSponsored(WALLET, IPaymaster.PostOpMode.postOpReverted, 21_000, 10 gwei);
        paymaster.postOp(IPaymaster.PostOpMode.postOpReverted, ctx, 21_000, 10 gwei);
    }

    function test_postOp_revertsWhen_notEntryPoint() public {
        bytes memory ctx = abi.encode(WALLET);
        vm.prank(ALICE);
        vm.expectRevert(IQuipPaymaster.InvalidEntryPoint.selector);
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, ctx, 21_000, 10 gwei);
    }

    /// @dev `postOp` decodes the sponsored wallet from `context`; the encoding
    ///      `abi.encode(address)` always produces 32 bytes. Any shorter context
    ///      must abort with an abi-decode revert rather than be silently
    ///      processed against a zero address. Locks down the invariant that
    ///      validatePaymasterUserOp is the sole authoritative source of
    ///      context bytes (always 32) and prevents a future regression where
    ///      a different code path emits a shorter context.
    function test_postOp_revertsWhen_contextTooShort() public {
        bytes memory shortCtx = new bytes(31); // one byte short
        vm.prank(ENTRY_POINT);
        vm.expectRevert();
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, shortCtx, 21_000, 10 gwei);
    }

    function test_postOp_revertsWhen_contextEmpty() public {
        bytes memory emptyCtx = "";
        vm.prank(ENTRY_POINT);
        vm.expectRevert();
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, emptyCtx, 21_000, 10 gwei);
    }
}
