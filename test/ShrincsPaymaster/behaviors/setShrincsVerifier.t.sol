// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for `setShrincsVerifier` (owner-only key rotation; cannot unset). No signature
///      is verified, so success + reverts are testable now.
contract ShrincsPaymaster_setShrincsVerifier is ShrincsPaymasterTest {
    bytes32 internal constant NEW_COMMITMENT = keccak256("rotated-verifier");
    uint32 internal constant SUITE = HashSuite.HASH_SUITE_ID;

    function test_setShrincsVerifier_rotatesAndBumpsEpoch() public {
        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SUITE, 16);

        (
            bytes32 commitment,
            ,
            uint256 keyVersion,
            uint32 maxSignatures,
            uint32 statefulLeavesUsed
        ) = paymaster.getShrincsVerifier();
        assertEq(commitment, NEW_COMMITMENT, "commitment rotated");
        assertEq(keyVersion, 1, "epoch bumped");
        assertEq(maxSignatures, 16, "budget updated");
        assertEq(statefulLeavesUsed, 0, "counter reset");
    }

    function test_setShrincsVerifier_freshBitmapNamespace() public {
        // Consume a leaf under epoch 0, then rotate; the new epoch's bitmap is empty.
        paymaster.harness_markLeafUsed(1);
        assertTrue(paymaster.isStatefulLeafUsed(1), "used under epoch 0");

        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SUITE, MAX_SIG);
        assertFalse(
            paymaster.isStatefulLeafUsed(1),
            "fresh namespace under epoch 1"
        );
    }

    function test_setShrincsVerifier_emitsShrincsVerifierSet() public {
        bytes32 prev = verifierCommitment;
        vm.recordLogs();
        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SUITE, MAX_SIG);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                IShrincsPaymaster.ShrincsVerifierSet.selector
            ) {
                found = true;
                assertEq(
                    logs[i].topics[1],
                    NEW_COMMITMENT,
                    "newCommitment indexed"
                );
                (bytes32 previousCommitment, , , ) = abi.decode(
                    logs[i].data,
                    (bytes32, uint32, uint32, uint256)
                );
                assertEq(
                    previousCommitment,
                    prev,
                    "previous commitment in data"
                );
            }
        }
        assertTrue(found, "ShrincsVerifierSet emitted");
    }

    /// @dev A hash suite the on-chain library does not verify must be rejected on rotation.
    function test_setShrincsVerifier_revertsWhen_unsupportedHashSuite() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.UnsupportedHashSuite.selector);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SHRINCS.HASH_SUITE_UNSUPPORTED, MAX_SIG);
    }

    /// @dev Epoch is MONOTONIC: each rotation increments it by exactly one and never resets, so a
    ///      leaf consumed under epoch N is invisible under epoch N+1 (the namespace is never reused —
    ///      the security property that lets one global key span rotations safely).
    function test_setShrincsVerifier_epochMonotonicAcrossRotations() public {
        vm.startPrank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SUITE, MAX_SIG); // epoch 0 -> 1
        vm.stopPrank();
        (, , uint256 epoch1, , ) = paymaster.getShrincsVerifier();
        assertEq(epoch1, 1, "first rotation -> epoch 1");

        paymaster.harness_markLeafUsed(1); // consume leaf 1 under epoch 1
        assertTrue(paymaster.isStatefulLeafUsed(1), "used under epoch 1");

        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SUITE, MAX_SIG); // epoch 1 -> 2
        (, , uint256 epoch2, , ) = paymaster.getShrincsVerifier();
        assertEq(epoch2, 2, "second rotation -> epoch 2 (never resets)");
        assertFalse(
            paymaster.isStatefulLeafUsed(1),
            "epoch 1's consumed leaf is invisible under epoch 2"
        );
    }

    /// @dev The used counter is reset on rotation even after real consumption (the base test rotates
    ///      from a zero counter, which a dropped reset would not reveal).
    function test_setShrincsVerifier_resetsCounterAfterUse() public {
        paymaster.harness_markLeafUsed(1);
        paymaster.harness_markLeafUsed(2);
        assertEq(paymaster.statefulLeavesUsed(), 2, "counter advanced");

        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SUITE, MAX_SIG);
        assertEq(
            paymaster.statefulLeavesUsed(),
            0,
            "counter reset on rotation"
        );
        assertEq(paymaster.remainingStatefulSignatures(), MAX_SIG);
    }

    /// @dev Pins the FULL `ShrincsVerifierSet` payload on rotation: hashSuite/maxSignatures echo
    ///      the args and keyVersion is the bumped epoch.
    function test_setShrincsVerifier_emitsFullPayload() public {
        vm.recordLogs();
        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SUITE, 16);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                IShrincsPaymaster.ShrincsVerifierSet.selector
            ) {
                found = true;
                (
                    bytes32 previousCommitment,
                    uint32 hashSuite,
                    uint32 maxSignatures,
                    uint256 keyVersion
                ) = abi.decode(logs[i].data, (bytes32, uint32, uint32, uint256));
                assertEq(previousCommitment, verifierCommitment, "previous commitment");
                assertEq(hashSuite, SUITE, "hashSuite in data");
                assertEq(maxSignatures, 16, "maxSignatures in data");
                assertEq(keyVersion, 1, "bumped epoch in data");
            }
        }
        assertTrue(found, "ShrincsVerifierSet emitted");
    }

    function test_setShrincsVerifier_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SUITE, MAX_SIG);
    }

    function test_setShrincsVerifier_revertsWhen_zeroCommitment() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.ZeroCommitment.selector);
        paymaster.setShrincsVerifier(bytes32(0), SUITE, MAX_SIG);
    }

    function test_setShrincsVerifier_revertsWhen_zeroMaxSignatures() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.ZeroMaxSignatures.selector);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, SUITE, 0);
    }
}
