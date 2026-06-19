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
        assertFalse(wallet.isStatefulLeafUsed(1), "same word, different bit untouched");

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
        assertFalse(wallet.isStatefulLeafUsed(1), "fresh namespace under epoch 1");

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
}
