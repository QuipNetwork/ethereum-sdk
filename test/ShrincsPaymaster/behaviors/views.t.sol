// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the paymaster view getters.
contract ShrincsPaymaster_views is ShrincsPaymasterTest {
    function test_owner() public view {
        assertEq(paymaster.owner(), OWNER);
    }

    function test_getShrincsVerifier_reflectsInstall() public view {
        (
            bytes32 commitment,
            ShrincsTypes.ParameterSetId parameterSetId,
            uint256 keyVersion,
            uint32 maxSignatures,
            uint32 statefulLeavesUsed
        ) = paymaster.getShrincsVerifier();
        assertEq(commitment, _bytes32(".verifierKey.publicKeyCommitment"));
        assertEq(uint8(parameterSetId), 0);
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

    function test_isStatefulLeafUsed_reflectsBitmap() public {
        assertFalse(paymaster.isStatefulLeafUsed(3));
        paymaster.harness_markLeafUsed(3);
        assertTrue(paymaster.isStatefulLeafUsed(3));
        assertFalse(paymaster.isStatefulLeafUsed(4));
    }
}
