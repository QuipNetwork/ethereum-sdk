// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_markStatefulLeafUsed` / `_isStatefulLeafUsed` bitmap
///      primitives, exercised directly via the harness against an explicit key epoch. These are
///      the replay-blocking core: a one-time leaf is set in `usedStatefulLeafBitmap[keyVersion]`
///      (word = leaf>>8, bit = leaf&0xff) and never cleared within an epoch.
contract ShrincsWallet__markStatefulLeafUsed is ShrincsWalletTest {
    function test_markStatefulLeafUsed_setsThenReads() public {
        assertFalse(wallet.exposed_isStatefulLeafUsed(0, 1), "initially unused");
        wallet.exposed_markStatefulLeafUsed(0, 1);
        assertTrue(wallet.exposed_isStatefulLeafUsed(0, 1), "marked used");
    }

    function test_markStatefulLeafUsed_isIdempotent() public {
        wallet.exposed_markStatefulLeafUsed(0, 5);
        wallet.exposed_markStatefulLeafUsed(0, 5); // marking again is a no-op
        assertTrue(wallet.exposed_isStatefulLeafUsed(0, 5));
        // Neighbours in the same word are untouched.
        assertFalse(wallet.exposed_isStatefulLeafUsed(0, 4));
        assertFalse(wallet.exposed_isStatefulLeafUsed(0, 6));
    }

    function test_markStatefulLeafUsed_distinctBitsSameWord() public {
        wallet.exposed_markStatefulLeafUsed(0, 1);
        wallet.exposed_markStatefulLeafUsed(0, 2);
        wallet.exposed_markStatefulLeafUsed(0, 254);
        assertTrue(wallet.exposed_isStatefulLeafUsed(0, 1));
        assertTrue(wallet.exposed_isStatefulLeafUsed(0, 2));
        assertTrue(wallet.exposed_isStatefulLeafUsed(0, 254));
        assertFalse(wallet.exposed_isStatefulLeafUsed(0, 3));
        assertFalse(wallet.exposed_isStatefulLeafUsed(0, 255));
    }

    function test_markStatefulLeafUsed_wordBoundary() public {
        // leaf 255 lives in word 0 bit 255; leaf 256 in word 1 bit 0 — independent words.
        wallet.exposed_markStatefulLeafUsed(0, 255);
        assertTrue(wallet.exposed_isStatefulLeafUsed(0, 255));
        assertFalse(wallet.exposed_isStatefulLeafUsed(0, 256), "next word untouched");

        wallet.exposed_markStatefulLeafUsed(0, 256);
        assertTrue(wallet.exposed_isStatefulLeafUsed(0, 256));
        assertFalse(wallet.exposed_isStatefulLeafUsed(0, 0), "word 0 bit 0 untouched");
        assertFalse(wallet.exposed_isStatefulLeafUsed(0, 511), "word 1 bit 255 untouched");
    }

    function test_markStatefulLeafUsed_isNamespacedByKeyVersion() public {
        wallet.exposed_markStatefulLeafUsed(0, 7);
        assertTrue(wallet.exposed_isStatefulLeafUsed(0, 7), "used under epoch 0");
        assertFalse(wallet.exposed_isStatefulLeafUsed(1, 7), "epoch 1 namespace is independent");

        wallet.exposed_markStatefulLeafUsed(1, 7);
        assertTrue(wallet.exposed_isStatefulLeafUsed(1, 7), "now used under epoch 1");
        assertTrue(wallet.exposed_isStatefulLeafUsed(0, 7), "epoch 0 history preserved");
    }

    function test_markStatefulLeafUsed_matchesPublicViewForCurrentEpoch() public {
        // The public `isStatefulLeafUsed(leaf)` reads the CURRENT keyVersion; it must agree with the
        // explicit-epoch internal read when the epoch matches.
        assertEq(wallet.keyVersion(), 0);
        wallet.exposed_markStatefulLeafUsed(0, 3);
        assertTrue(wallet.isStatefulLeafUsed(3), "public view sees the current-epoch mark");
        assertEq(
            wallet.isStatefulLeafUsed(3),
            wallet.exposed_isStatefulLeafUsed(0, 3),
            "public and explicit-epoch reads agree"
        );
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    function testFuzz_markStatefulLeafUsed_setsThenReads(uint256 epoch, uint256 leaf) public {
        assertFalse(wallet.exposed_isStatefulLeafUsed(epoch, leaf), "initially unused");
        wallet.exposed_markStatefulLeafUsed(epoch, leaf);
        assertTrue(wallet.exposed_isStatefulLeafUsed(epoch, leaf), "marked used");
    }

    /// @dev The (leaf) → (word = leaf>>8, bit = leaf&0xff) map is injective, so marking any one leaf
    ///      must never set the bit of a different leaf in the same epoch.
    function testFuzz_markStatefulLeafUsed_independence(uint256 epoch, uint256 a, uint256 b) public {
        vm.assume(a != b);
        wallet.exposed_markStatefulLeafUsed(epoch, a);
        assertTrue(wallet.exposed_isStatefulLeafUsed(epoch, a), "marked leaf set");
        assertFalse(wallet.exposed_isStatefulLeafUsed(epoch, b), "other leaf untouched");
    }

    /// @dev A mark under one key epoch must be invisible under any other epoch (fresh bitmap
    ///      namespace per `keyVersion`), and never leaks back into the marked epoch.
    function testFuzz_markStatefulLeafUsed_namespacing(uint256 epochA, uint256 epochB, uint256 leaf) public {
        vm.assume(epochA != epochB);
        wallet.exposed_markStatefulLeafUsed(epochA, leaf);
        assertTrue(wallet.exposed_isStatefulLeafUsed(epochA, leaf), "set under epochA");
        assertFalse(wallet.exposed_isStatefulLeafUsed(epochB, leaf), "invisible under epochB");
    }

    /// @dev Marking is idempotent and only ever sets bits (never clears): a second mark of any leaf
    ///      leaves both it and a previously-marked neighbour set.
    function testFuzz_markStatefulLeafUsed_idempotentMonotonic(uint256 epoch, uint256 a, uint256 b) public {
        vm.assume(a != b);
        wallet.exposed_markStatefulLeafUsed(epoch, a);
        wallet.exposed_markStatefulLeafUsed(epoch, b);
        wallet.exposed_markStatefulLeafUsed(epoch, b); // repeat is a no-op
        assertTrue(wallet.exposed_isStatefulLeafUsed(epoch, a), "first mark preserved");
        assertTrue(wallet.exposed_isStatefulLeafUsed(epoch, b), "second mark set");
    }
}
