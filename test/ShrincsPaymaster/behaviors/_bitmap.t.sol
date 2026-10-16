// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the keyVersion-namespaced used-leaf bitmap (word = leaf>>8, bit =
///      leaf&0xff), via `harness_markLeafUsed` + `harness_setKeyVersion` + the `isStatefulLeafUsed`
///      view (which ignores the budget, so boundaries beyond maxSignatures are observable).
contract ShrincsPaymaster__bitmap is ShrincsPaymasterTest {
    function test_bitmap_wordBoundary255And256() public {
        paymaster.harness_markLeafUsed(255); // word 0, bit 255
        assertTrue(paymaster.isStatefulLeafUsed(255));
        assertFalse(paymaster.isStatefulLeafUsed(256), "next word untouched");

        paymaster.harness_markLeafUsed(256); // word 1, bit 0
        assertTrue(paymaster.isStatefulLeafUsed(256));
        assertFalse(paymaster.isStatefulLeafUsed(0), "word 0 bit 0 untouched");
        assertFalse(
            paymaster.isStatefulLeafUsed(257),
            "word 1 bit 1 untouched"
        );
    }

    function test_bitmap_independentBitsAcrossWords() public {
        paymaster.harness_markLeafUsed(1);
        paymaster.harness_markLeafUsed(257);
        assertTrue(paymaster.isStatefulLeafUsed(1));
        assertTrue(paymaster.isStatefulLeafUsed(257));
        assertFalse(paymaster.isStatefulLeafUsed(256));
        assertFalse(paymaster.isStatefulLeafUsed(2));
    }

    function test_bitmap_namespacedByKeyVersion() public {
        paymaster.harness_markLeafUsed(1);
        assertTrue(paymaster.isStatefulLeafUsed(1), "used under epoch 0");

        paymaster.harness_setKeyVersion(1);
        assertFalse(
            paymaster.isStatefulLeafUsed(1),
            "fresh namespace under epoch 1"
        );

        paymaster.harness_setKeyVersion(0);
        assertTrue(
            paymaster.isStatefulLeafUsed(1),
            "epoch 0 history preserved"
        );
    }

    function test_bitmap_countersTrackUsage() public {
        assertEq(paymaster.statefulLeavesUsed(), 0);
        assertEq(paymaster.remainingStatefulSignatures(), MAX_SIG);
        paymaster.harness_markLeafUsed(1);
        paymaster.harness_markLeafUsed(2);
        assertEq(paymaster.statefulLeavesUsed(), 2);
        assertEq(paymaster.remainingStatefulSignatures(), MAX_SIG - 2);
    }

    /// @dev Off-by-one guard on `1 << (leaf & 0xff)`: marking a bit must not touch its neighbours.
    function test_bitmap_adjacentBitsIsolated() public {
        paymaster.harness_markLeafUsed(5); // word 0, bit 5
        assertTrue(paymaster.isStatefulLeafUsed(5));
        assertFalse(paymaster.isStatefulLeafUsed(4), "bit 4 untouched");
        assertFalse(paymaster.isStatefulLeafUsed(6), "bit 6 untouched");
    }

    /// @dev Exercises the `>> 8` word index beyond the first two words.
    function test_bitmap_higherWordIndices() public {
        paymaster.harness_markLeafUsed(512); // word 2, bit 0
        paymaster.harness_markLeafUsed(767); // word 2, bit 255
        paymaster.harness_markLeafUsed(768); // word 3, bit 0
        assertTrue(paymaster.isStatefulLeafUsed(512));
        assertTrue(paymaster.isStatefulLeafUsed(767));
        assertTrue(paymaster.isStatefulLeafUsed(768));
        assertFalse(
            paymaster.isStatefulLeafUsed(513),
            "word 2 bit 1 untouched"
        );
        assertFalse(
            paymaster.isStatefulLeafUsed(511),
            "word 1 bit 255 untouched"
        );
        assertFalse(
            paymaster.isStatefulLeafUsed(769),
            "word 3 bit 1 untouched"
        );
    }

    /// @dev The word-0/bit-0 corner. (Leaf 0 is rejected before marking in production, but the
    ///      bitmap helper itself must still index it correctly.)
    function test_bitmap_leafZeroCorner() public {
        assertFalse(paymaster.isStatefulLeafUsed(0));
        paymaster.harness_markLeafUsed(0); // word 0, bit 0
        assertTrue(paymaster.isStatefulLeafUsed(0));
        assertFalse(paymaster.isStatefulLeafUsed(1), "bit 1 untouched");
        assertFalse(
            paymaster.isStatefulLeafUsed(256),
            "word 1 bit 0 untouched"
        );
    }

    /// @dev Two epochs hold their OWN bits simultaneously — neither sees the other's leaves.
    function test_bitmap_multipleEpochsIndependentlyPopulated() public {
        paymaster.harness_markLeafUsed(1); // epoch 0
        paymaster.harness_setKeyVersion(1);
        paymaster.harness_markLeafUsed(2); // epoch 1
        assertTrue(paymaster.isStatefulLeafUsed(2), "epoch 1 holds leaf 2");
        assertFalse(
            paymaster.isStatefulLeafUsed(1),
            "epoch 1 does not see epoch 0's leaf 1"
        );

        paymaster.harness_setKeyVersion(0);
        assertTrue(paymaster.isStatefulLeafUsed(1), "epoch 0 holds leaf 1");
        assertFalse(
            paymaster.isStatefulLeafUsed(2),
            "epoch 0 does not see epoch 1's leaf 2"
        );
    }

    /// @dev Consuming the whole budget drives `remainingStatefulSignatures` to exactly zero.
    function test_bitmap_fullBudgetRemainingZero() public {
        for (uint32 leaf = 1; leaf <= MAX_SIG; leaf++) {
            paymaster.harness_markLeafUsed(leaf);
        }
        assertEq(paymaster.statefulLeavesUsed(), MAX_SIG);
        assertEq(paymaster.remainingStatefulSignatures(), 0);
        for (uint32 leaf = 1; leaf <= MAX_SIG; leaf++) {
            assertTrue(
                paymaster.isStatefulLeafUsed(leaf),
                "every budgeted leaf marked"
            );
        }
    }
}
