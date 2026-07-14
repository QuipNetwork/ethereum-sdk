// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.2.0/contracts/ShrincsTypes.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the internal `_verifyAndAdvance` (the replay-blocking core), via the
///      harness. Returns false on every guard/verify failure; the success consume (including
///      out-of-order leaves) is covered with the dedicated paymaster vectors.
contract ShrincsPaymaster__verifyAndAdvance is ShrincsPaymasterTest {
    address internal constant SENDER = address(0xA11CE);

    function _call(
        ShrincsTypes.StatefulSignature memory sig
    ) internal returns (bool) {
        PackedUserOperation memory op = _userOp(SENDER, _pmData(_pk(), sig));
        return paymaster.exposed_verifyAndAdvance(op);
    }

    function test_verifyAndAdvance_falseWhen_leafZero() public {
        assertFalse(_call(_statefulSigWithLeaf(0)));
        assertEq(paymaster.statefulLeavesUsed(), 0);
    }

    function test_verifyAndAdvance_falseWhen_leafOverBudget() public {
        assertFalse(_call(_statefulSigWithLeaf(uint256(MAX_SIG) + 1)));
    }

    function test_verifyAndAdvance_falseWhen_leafAlreadyUsed() public {
        paymaster.harness_markLeafUsed(1);
        assertFalse(_call(_statefulSigWithLeaf(1)));
    }

    function test_verifyAndAdvance_falseWhen_invalidSignature() public {
        assertFalse(_call(_wrongContextStatefulSig()));
        assertFalse(
            paymaster.isStatefulLeafUsed(1),
            "leaf not consumed on invalid signature"
        );
    }

    /// @dev Boundary: leaf == maxSignatures is IN budget, so it must pass the budget guard and reach
    ///      verify (where the synthetic, signature-less blob fails). Returns false, consumes nothing —
    ///      distinct from the over-budget case which is rejected before verify. Pins `>` vs `>=`.
    function test_verifyAndAdvance_falseWhen_leafAtBudget() public {
        assertFalse(_call(_statefulSigWithLeaf(MAX_SIG)));
        assertFalse(
            paymaster.isStatefulLeafUsed(MAX_SIG),
            "leaf not consumed when verify fails at the budget boundary"
        );
        assertEq(paymaster.statefulLeavesUsed(), 0);
    }

    /* ──────────────────────── sponsorship success ──────────────────────────── */

    function test_verifyAndAdvance_consumesLeafOnSuccess() public {
        (PackedUserOperation memory op, uint32 leaf) = _sponsorUserOp(0);
        assertTrue(
            paymaster.exposed_verifyAndAdvance(op),
            "valid sponsorship verifies"
        );
        assertTrue(paymaster.isStatefulLeafUsed(leaf), "leaf consumed");
        assertEq(paymaster.statefulLeavesUsed(), 1, "counter incremented");
    }

    function test_verifyAndAdvance_outOfOrderLeaves() public {
        // Submit leaf 3 then leaf 2: the bitmap accepts leaves in any order.
        (PackedUserOperation memory opHigh, uint32 leafHigh) = _sponsorUserOp(
            2
        ); // leaf 3
        (PackedUserOperation memory opLow, uint32 leafLow) = _sponsorUserOp(1); // leaf 2
        assertTrue(
            paymaster.exposed_verifyAndAdvance(opHigh),
            "higher leaf lands first"
        );
        assertTrue(
            paymaster.exposed_verifyAndAdvance(opLow),
            "lower leaf accepted out of order"
        );
        assertTrue(paymaster.isStatefulLeafUsed(leafHigh));
        assertTrue(paymaster.isStatefulLeafUsed(leafLow));
    }
}
