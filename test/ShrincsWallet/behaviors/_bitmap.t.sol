// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the keyVersion-namespaced used-leaf bitmap (word = leaf>>8, bit =
///      leaf&0xff). Exercised via the public `isStatefulLeafUsed` view + `harness_markLeafUsed` +
///      `harness_setKeyVersion`. The view ignores the leaf budget, so word boundaries beyond
///      maxSignatures are observable.
contract ShrincsWallet__bitmap is ShrincsWalletTest {
    function test_bitmap_wordBoundary255And256() public {
        wallet.harness_markLeafUsed(255); // word 0, bit 255
        assertTrue(wallet.isStatefulLeafUsed(255));
        assertFalse(wallet.isStatefulLeafUsed(256), "next word untouched");
        assertFalse(
            wallet.isStatefulLeafUsed(1),
            "same word, different bit untouched"
        );

        wallet.harness_markLeafUsed(256); // word 1, bit 0
        assertTrue(wallet.isStatefulLeafUsed(256));
        assertFalse(wallet.isStatefulLeafUsed(0), "word 0 bit 0 untouched");
        assertFalse(wallet.isStatefulLeafUsed(257), "word 1 bit 1 untouched");
    }

    function test_bitmap_independentBitsAcrossWords() public {
        wallet.harness_markLeafUsed(1); // word 0, bit 1
        wallet.harness_markLeafUsed(257); // word 1, bit 1
        assertTrue(wallet.isStatefulLeafUsed(1));
        assertTrue(wallet.isStatefulLeafUsed(257));
        assertFalse(wallet.isStatefulLeafUsed(256));
        assertFalse(wallet.isStatefulLeafUsed(2));
    }

    function test_bitmap_namespacedByKeyVersion() public {
        wallet.harness_markLeafUsed(1);
        assertTrue(wallet.isStatefulLeafUsed(1), "used under epoch 0");

        wallet.harness_setKeyVersion(1);
        assertFalse(
            wallet.isStatefulLeafUsed(1),
            "fresh namespace under epoch 1"
        );

        wallet.harness_setKeyVersion(0);
        assertTrue(wallet.isStatefulLeafUsed(1), "epoch 0 history preserved");
    }

    function test_bitmap_countersTrackUsage() public {
        assertEq(wallet.statefulLeavesUsed(), 0);
        assertEq(wallet.remainingStatefulSignatures(), MAX_SIG);

        wallet.harness_markLeafUsed(1);
        wallet.harness_markLeafUsed(2);
        assertEq(wallet.statefulLeavesUsed(), 2);
        assertEq(wallet.remainingStatefulSignatures(), MAX_SIG - 2);
    }

    /// @dev Off-by-one guard on `1 << (leaf & 0xff)`: marking a bit must not touch its neighbours.
    function test_bitmap_adjacentBitsIsolated() public {
        wallet.harness_markLeafUsed(5); // word 0, bit 5
        assertTrue(wallet.isStatefulLeafUsed(5));
        assertFalse(wallet.isStatefulLeafUsed(4), "bit 4 untouched");
        assertFalse(wallet.isStatefulLeafUsed(6), "bit 6 untouched");
    }

    /// @dev Exercises the `>> 8` word index beyond the first two words.
    function test_bitmap_higherWordIndices() public {
        wallet.harness_markLeafUsed(512); // word 2, bit 0
        wallet.harness_markLeafUsed(767); // word 2, bit 255
        wallet.harness_markLeafUsed(768); // word 3, bit 0
        assertTrue(wallet.isStatefulLeafUsed(512));
        assertTrue(wallet.isStatefulLeafUsed(767));
        assertTrue(wallet.isStatefulLeafUsed(768));
        assertFalse(wallet.isStatefulLeafUsed(513), "word 2 bit 1 untouched");
        assertFalse(wallet.isStatefulLeafUsed(511), "word 1 bit 255 untouched");
        assertFalse(wallet.isStatefulLeafUsed(769), "word 3 bit 1 untouched");
    }

    /// @dev The word-0/bit-0 corner. (Leaf 0 is rejected before marking in production, but the
    ///      bitmap helper itself must still index it correctly.)
    function test_bitmap_leafZeroCorner() public {
        assertFalse(wallet.isStatefulLeafUsed(0));
        wallet.harness_markLeafUsed(0); // word 0, bit 0
        assertTrue(wallet.isStatefulLeafUsed(0));
        assertFalse(wallet.isStatefulLeafUsed(1), "bit 1 untouched");
        assertFalse(wallet.isStatefulLeafUsed(256), "word 1 bit 0 untouched");
    }

    /// @dev Two epochs hold their OWN bits simultaneously — neither sees the other's leaves.
    function test_bitmap_multipleEpochsIndependentlyPopulated() public {
        wallet.harness_markLeafUsed(1); // epoch 0
        wallet.harness_setKeyVersion(1);
        wallet.harness_markLeafUsed(2); // epoch 1
        assertTrue(wallet.isStatefulLeafUsed(2), "epoch 1 holds leaf 2");
        assertFalse(
            wallet.isStatefulLeafUsed(1),
            "epoch 1 does not see epoch 0's leaf 1"
        );

        wallet.harness_setKeyVersion(0);
        assertTrue(wallet.isStatefulLeafUsed(1), "epoch 0 holds leaf 1");
        assertFalse(
            wallet.isStatefulLeafUsed(2),
            "epoch 0 does not see epoch 1's leaf 2"
        );
    }

    /// @dev Consuming the whole budget drives `remainingStatefulSignatures` to exactly zero.
    function test_bitmap_fullBudgetRemainingZero() public {
        for (uint32 leaf = 1; leaf <= MAX_SIG; leaf++) {
            wallet.harness_markLeafUsed(leaf);
        }
        assertEq(wallet.statefulLeavesUsed(), MAX_SIG);
        assertEq(wallet.remainingStatefulSignatures(), 0);
        for (uint32 leaf = 1; leaf <= MAX_SIG; leaf++) {
            assertTrue(
                wallet.isStatefulLeafUsed(leaf),
                "every budgeted leaf marked"
            );
        }
    }
}
