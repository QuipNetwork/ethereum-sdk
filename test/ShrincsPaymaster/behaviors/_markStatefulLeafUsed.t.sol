// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the internal `_markStatefulLeafUsed` / `_isStatefulLeafUsed` bitmap
///      primitives, exercised directly via the harness against an explicit key epoch. These are
///      the replay-blocking core: a one-time leaf is set in `usedStatefulLeafBitmap[keyVersion]`
///      (word = leaf>>8, bit = leaf&0xff) and never cleared within an epoch.
contract ShrincsPaymaster__markStatefulLeafUsed is ShrincsPaymasterTest {
    function test_markStatefulLeafUsed_setsThenReads() public {
        assertFalse(
            paymaster.exposed_isStatefulLeafUsed(0, 1),
            "initially unused"
        );
        paymaster.exposed_markStatefulLeafUsed(0, 1);
        assertTrue(paymaster.exposed_isStatefulLeafUsed(0, 1), "marked used");
    }

    function test_markStatefulLeafUsed_isIdempotent() public {
        paymaster.exposed_markStatefulLeafUsed(0, 5);
        paymaster.exposed_markStatefulLeafUsed(0, 5); // marking again is a no-op
        assertTrue(paymaster.exposed_isStatefulLeafUsed(0, 5));
        // Neighbours in the same word are untouched.
        assertFalse(paymaster.exposed_isStatefulLeafUsed(0, 4));
        assertFalse(paymaster.exposed_isStatefulLeafUsed(0, 6));
    }

    function test_markStatefulLeafUsed_distinctBitsSameWord() public {
        paymaster.exposed_markStatefulLeafUsed(0, 1);
        paymaster.exposed_markStatefulLeafUsed(0, 2);
        paymaster.exposed_markStatefulLeafUsed(0, 254);
        assertTrue(paymaster.exposed_isStatefulLeafUsed(0, 1));
        assertTrue(paymaster.exposed_isStatefulLeafUsed(0, 2));
        assertTrue(paymaster.exposed_isStatefulLeafUsed(0, 254));
        assertFalse(paymaster.exposed_isStatefulLeafUsed(0, 3));
        assertFalse(paymaster.exposed_isStatefulLeafUsed(0, 255));
    }

    function test_markStatefulLeafUsed_wordBoundary() public {
        // leaf 255 lives in word 0 bit 255; leaf 256 in word 1 bit 0 — independent words.
        paymaster.exposed_markStatefulLeafUsed(0, 255);
        assertTrue(paymaster.exposed_isStatefulLeafUsed(0, 255));
        assertFalse(
            paymaster.exposed_isStatefulLeafUsed(0, 256),
            "next word untouched"
        );

        paymaster.exposed_markStatefulLeafUsed(0, 256);
        assertTrue(paymaster.exposed_isStatefulLeafUsed(0, 256));
        assertFalse(
            paymaster.exposed_isStatefulLeafUsed(0, 0),
            "word 0 bit 0 untouched"
        );
        assertFalse(
            paymaster.exposed_isStatefulLeafUsed(0, 511),
            "word 1 bit 255 untouched"
        );
    }

    function test_markStatefulLeafUsed_isNamespacedByKeyVersion() public {
        paymaster.exposed_markStatefulLeafUsed(0, 7);
        assertTrue(
            paymaster.exposed_isStatefulLeafUsed(0, 7),
            "used under epoch 0"
        );
        assertFalse(
            paymaster.exposed_isStatefulLeafUsed(1, 7),
            "epoch 1 namespace is independent"
        );

        paymaster.exposed_markStatefulLeafUsed(1, 7);
        assertTrue(
            paymaster.exposed_isStatefulLeafUsed(1, 7),
            "now used under epoch 1"
        );
        assertTrue(
            paymaster.exposed_isStatefulLeafUsed(0, 7),
            "epoch 0 history preserved"
        );
    }

    function test_markStatefulLeafUsed_matchesPublicViewForCurrentEpoch()
        public
    {
        // The public `isStatefulLeafUsed(leaf)` reads the CURRENT keyVersion; it must agree with the
        // explicit-epoch internal read when the epoch matches.
        (, , uint256 keyVersion, , ) = paymaster.getShrincsVerifier();
        assertEq(keyVersion, 0);
        paymaster.exposed_markStatefulLeafUsed(0, 3);
        assertTrue(
            paymaster.isStatefulLeafUsed(3),
            "public view sees the current-epoch mark"
        );
        assertEq(
            paymaster.isStatefulLeafUsed(3),
            paymaster.exposed_isStatefulLeafUsed(0, 3),
            "public and explicit-epoch reads agree"
        );
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    function testFuzz_markStatefulLeafUsed_setsThenReads(
        uint256 epoch,
        uint256 leaf
    ) public {
        assertFalse(
            paymaster.exposed_isStatefulLeafUsed(epoch, leaf),
            "initially unused"
        );
        paymaster.exposed_markStatefulLeafUsed(epoch, leaf);
        assertTrue(
            paymaster.exposed_isStatefulLeafUsed(epoch, leaf),
            "marked used"
        );
    }

    /// @dev The (leaf) → (word = leaf>>8, bit = leaf&0xff) map is injective, so marking any one leaf
    ///      must never set the bit of a different leaf in the same epoch.
    function testFuzz_markStatefulLeafUsed_independence(
        uint256 epoch,
        uint256 a,
        uint256 b
    ) public {
        vm.assume(a != b);
        paymaster.exposed_markStatefulLeafUsed(epoch, a);
        assertTrue(
            paymaster.exposed_isStatefulLeafUsed(epoch, a),
            "marked leaf set"
        );
        assertFalse(
            paymaster.exposed_isStatefulLeafUsed(epoch, b),
            "other leaf untouched"
        );
    }

    /// @dev A mark under one key epoch must be invisible under any other epoch (fresh bitmap
    ///      namespace per `keyVersion`).
    function testFuzz_markStatefulLeafUsed_namespacing(
        uint256 epochA,
        uint256 epochB,
        uint256 leaf
    ) public {
        vm.assume(epochA != epochB);
        paymaster.exposed_markStatefulLeafUsed(epochA, leaf);
        assertTrue(
            paymaster.exposed_isStatefulLeafUsed(epochA, leaf),
            "set under epochA"
        );
        assertFalse(
            paymaster.exposed_isStatefulLeafUsed(epochB, leaf),
            "invisible under epochB"
        );
    }

    /// @dev Marking is idempotent and only ever sets bits (never clears): a second mark of any leaf
    ///      leaves both it and a previously-marked neighbour set.
    function testFuzz_markStatefulLeafUsed_idempotentMonotonic(
        uint256 epoch,
        uint256 a,
        uint256 b
    ) public {
        vm.assume(a != b);
        paymaster.exposed_markStatefulLeafUsed(epoch, a);
        paymaster.exposed_markStatefulLeafUsed(epoch, b);
        paymaster.exposed_markStatefulLeafUsed(epoch, b); // repeat is a no-op
        assertTrue(
            paymaster.exposed_isStatefulLeafUsed(epoch, a),
            "first mark preserved"
        );
        assertTrue(
            paymaster.exposed_isStatefulLeafUsed(epoch, b),
            "second mark set"
        );
    }
}
