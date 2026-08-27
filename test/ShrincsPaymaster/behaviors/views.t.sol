// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the paymaster view getters.
contract ShrincsPaymaster_views is ShrincsPaymasterTest {
    function test_owner() public view {
        assertEq(paymaster.owner(), OWNER);
    }

    function test_getShrincsVerifier_reflectsInstall() public view {
        (
            bytes32 commitment,
            uint32 hashSuite,
            uint256 keyVersion,
            uint32 maxSignatures,
            uint32 statefulLeavesUsed
        ) = paymaster.getShrincsVerifier();
        assertEq(commitment, verifierCommitment);
        assertEq(hashSuite, HashSuite.HASH_SUITE_ID);
        assertEq(keyVersion, 0);
        assertEq(maxSignatures, MAX_SIG);
        assertEq(statefulLeavesUsed, 0);
    }

    function test_remainingStatefulSignatures_tracksUsage() public {
        assertEq(paymaster.remainingStatefulSignatures(), MAX_SIG);
        paymaster.harness_markLeafUsed(1);
        assertEq(paymaster.statefulLeavesUsed(), 1);
        assertEq(paymaster.remainingStatefulSignatures(), MAX_SIG - 1);
    }

    /// @dev The advisory counter must never underflow/revert if it ever drifts above
    ///      `maxSignatures`; the leaf bitmap is the real anti-replay mechanism.
    function test_remainingStatefulSignatures_saturatesOnDrift() public {
        paymaster.harness_markLeafUsed(1);
        paymaster.harness_markLeafUsed(2);
        assertEq(paymaster.statefulLeavesUsed(), 2);
        // Force the counter above max: reinstall with a smaller max than the used count.
        paymaster.harness_install(verifierCommitment, 1);
        assertEq(paymaster.remainingStatefulSignatures(), 0);
        // Equal counts also saturate to zero.
        paymaster.harness_install(verifierCommitment, 2);
        assertEq(paymaster.remainingStatefulSignatures(), 0);
    }

    function test_isStatefulLeafUsed_reflectsBitmap() public {
        assertFalse(paymaster.isStatefulLeafUsed(3));
        paymaster.harness_markLeafUsed(3);
        assertTrue(paymaster.isStatefulLeafUsed(3));
        assertFalse(paymaster.isStatefulLeafUsed(4));
    }

    function test_statefulLeafBitmapWord_packsConsumedLeaves() public {
        assertEq(paymaster.statefulLeafBitmapWord(0), 0, "word 0 starts empty");
        paymaster.harness_markLeafUsed(3);
        paymaster.harness_markLeafUsed(7);
        assertEq(
            paymaster.statefulLeafBitmapWord(0),
            (uint256(1) << 3) | (uint256(1) << 7),
            "word 0 packs consumed leaves 3 and 7"
        );
        assertEq(paymaster.statefulLeafBitmapWord(1), 0, "untouched word reads zero");
    }
}
