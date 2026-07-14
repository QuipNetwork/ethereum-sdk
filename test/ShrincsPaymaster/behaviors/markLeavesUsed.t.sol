// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for `markLeavesUsed` (owner-only FIAT revocation of outstanding sponsorship
///      leaves; mirrors the wallet's batch semantics — idempotent skip on already-used targets,
///      loud revert on out-of-range ones).
contract ShrincsPaymaster_markLeavesUsed is ShrincsPaymasterTest {
    function test_markLeavesUsed_marksLeavesAndCounts() public {
        uint32[] memory leaves = new uint32[](2);
        leaves[0] = 2;
        leaves[1] = 5;

        vm.prank(OWNER);
        paymaster.markLeavesUsed(leaves);

        assertTrue(paymaster.isStatefulLeafUsed(2), "leaf 2 revoked");
        assertTrue(paymaster.isStatefulLeafUsed(5), "leaf 5 revoked");
        assertFalse(paymaster.isStatefulLeafUsed(3), "untargeted leaf untouched");
        assertEq(paymaster.statefulLeavesUsed(), 2, "counter advanced per revocation");
        assertEq(paymaster.remainingStatefulSignatures(), MAX_SIG - 2);
    }

    function test_markLeavesUsed_emitsLeafRevoked() public {
        uint32[] memory leaves = new uint32[](2);
        leaves[0] = 1;
        leaves[1] = 7;

        vm.expectEmit(true, true, false, true, address(paymaster));
        emit IShrincsPaymaster.LeafRevoked(1, 0);
        vm.expectEmit(true, true, false, true, address(paymaster));
        emit IShrincsPaymaster.LeafRevoked(7, 0);
        vm.prank(OWNER);
        paymaster.markLeavesUsed(leaves);
    }

    /// @dev Already-consumed targets are skipped with an event, never reverted — a sponsorship
    ///      racing its own revocation must not brick the batch.
    function test_markLeavesUsed_skipsAlreadyUsed() public {
        paymaster.harness_markLeafUsed(3);
        assertEq(paymaster.statefulLeavesUsed(), 1, "one consumed pre-batch");

        uint32[] memory leaves = new uint32[](2);
        leaves[0] = 3; // already used -> skip
        leaves[1] = 4; // fresh -> revoke

        vm.expectEmit(true, true, false, true, address(paymaster));
        emit IShrincsPaymaster.LeafRevocationSkipped(3, 0);
        vm.expectEmit(true, true, false, true, address(paymaster));
        emit IShrincsPaymaster.LeafRevoked(4, 0);
        vm.prank(OWNER);
        paymaster.markLeavesUsed(leaves);

        assertTrue(paymaster.isStatefulLeafUsed(3), "leaf 3 still used");
        assertTrue(paymaster.isStatefulLeafUsed(4), "leaf 4 revoked");
        assertEq(paymaster.statefulLeavesUsed(), 2, "skip did not double-count");
    }

    /// @dev Duplicates inside one batch: first occurrence revokes, second is an idempotent skip.
    function test_markLeavesUsed_skipsDuplicatesInBatch() public {
        uint32[] memory leaves = new uint32[](2);
        leaves[0] = 6;
        leaves[1] = 6;

        vm.expectEmit(true, true, false, true, address(paymaster));
        emit IShrincsPaymaster.LeafRevoked(6, 0);
        vm.expectEmit(true, true, false, true, address(paymaster));
        emit IShrincsPaymaster.LeafRevocationSkipped(6, 0);
        vm.prank(OWNER);
        paymaster.markLeavesUsed(leaves);

        assertEq(paymaster.statefulLeavesUsed(), 1, "duplicate counted once");
    }

    /// @dev The point of the function: an outstanding, validly signed sponsorship is dead after
    ///      its leaf is revoked (rejected as a stale leaf during validation).
    function test_markLeavesUsed_blocksOutstandingSponsorship() public {
        (PackedUserOperation memory op, uint32 leaf) = _sponsorUserOp(0);

        uint32[] memory leaves = new uint32[](1);
        leaves[0] = leaf;
        vm.prank(OWNER);
        paymaster.markLeavesUsed(leaves);

        vm.expectEmit(true, false, false, true, address(paymaster));
        emit IShrincsPaymaster.PaymasterValidationRejected(
            SPONSOR_SENDER,
            IShrincsPaymaster.PaymasterValidationFailure.StaleStatefulLeaf
        );
        (, uint256 validationData) = _validate(op);
        assertEq(validationData, 1, "revoked-leaf sponsorship rejected");
    }

    /// @dev Out-of-range targets revert the WHOLE batch (client bug, not a race): nothing before
    ///      the bad entry is committed.
    function test_markLeavesUsed_outOfRangeRevertsWholeBatch() public {
        uint32[] memory leaves = new uint32[](2);
        leaves[0] = 2;
        leaves[1] = MAX_SIG + 1;

        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsPaymaster.LeafOutOfRange.selector, MAX_SIG + 1)
        );
        paymaster.markLeavesUsed(leaves);

        assertFalse(paymaster.isStatefulLeafUsed(2), "no partial commit on batch revert");
        assertEq(paymaster.statefulLeavesUsed(), 0, "counter untouched on batch revert");
    }

    function test_markLeavesUsed_revertsWhen_leafZero() public {
        uint32[] memory leaves = new uint32[](1);
        leaves[0] = 0;

        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsPaymaster.LeafOutOfRange.selector, 0)
        );
        paymaster.markLeavesUsed(leaves);
    }

    function test_markLeavesUsed_revertsWhen_empty() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.EmptyLeaves.selector);
        paymaster.markLeavesUsed(new uint32[](0));
    }

    function test_markLeavesUsed_revertsWhen_notOwner() public {
        uint32[] memory leaves = new uint32[](1);
        leaves[0] = 1;

        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.markLeavesUsed(leaves);
    }
}
