// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for `setShrincsVerifier` (owner-only key rotation; cannot unset). No signature
///      is verified, so success + reverts are testable now.
contract ShrincsPaymaster_setShrincsVerifier is ShrincsPaymasterTest {
    bytes32 internal constant NEW_COMMITMENT = keccak256("rotated-verifier");

    function test_setShrincsVerifier_rotatesAndBumpsEpoch() public {
        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 0, 16);

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
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 0, MAX_SIG);
        assertFalse(
            paymaster.isStatefulLeafUsed(1),
            "fresh namespace under epoch 1"
        );
    }

    function test_setShrincsVerifier_emitsShrincsVerifierSet() public {
        bytes32 prev = _bytes32(".verifierKey.publicKeyCommitment");
        vm.recordLogs();
        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 0, MAX_SIG);

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
                    (bytes32, uint8, uint32, uint256)
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

    /// @dev `parameterSetId` is rotated (persisted), not just commitment/budget. The base install uses
    ///      0, so rotate to the `Unsupported` member (1) and read it back.
    function test_setShrincsVerifier_rotatesParameterSetId() public {
        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 1, MAX_SIG);
        (, ShrincsTypes.ParameterSetId parameterSetId, , , ) = paymaster
            .getShrincsVerifier();
        assertEq(uint8(parameterSetId), 1, "parameterSetId rotated");
    }

    /// @dev Epoch is MONOTONIC: each rotation increments it by exactly one and never resets, so a
    ///      leaf consumed under epoch N is invisible under epoch N+1 (the namespace is never reused —
    ///      the security property that lets one global key span rotations safely).
    function test_setShrincsVerifier_epochMonotonicAcrossRotations() public {
        vm.startPrank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 0, MAX_SIG); // epoch 0 -> 1
        vm.stopPrank();
        (, , uint256 epoch1, , ) = paymaster.getShrincsVerifier();
        assertEq(epoch1, 1, "first rotation -> epoch 1");

        paymaster.harness_markLeafUsed(1); // consume leaf 1 under epoch 1
        assertTrue(paymaster.isStatefulLeafUsed(1), "used under epoch 1");

        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 0, MAX_SIG); // epoch 1 -> 2
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
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 0, MAX_SIG);
        assertEq(
            paymaster.statefulLeavesUsed(),
            0,
            "counter reset on rotation"
        );
        assertEq(paymaster.remainingStatefulSignatures(), MAX_SIG);
    }

    /// @dev Pins the FULL `ShrincsVerifierSet` payload on rotation: parameterSetId/maxSignatures echo
    ///      the args and keyVersion is the bumped epoch.
    function test_setShrincsVerifier_emitsFullPayload() public {
        vm.recordLogs();
        vm.prank(OWNER);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 1, 16);

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
                    uint8 parameterSetId,
                    uint32 maxSignatures,
                    uint256 keyVersion
                ) = abi.decode(logs[i].data, (bytes32, uint8, uint32, uint256));
                assertEq(
                    previousCommitment,
                    _bytes32(".verifierKey.publicKeyCommitment"),
                    "previous commitment"
                );
                assertEq(parameterSetId, 1, "parameterSetId in data");
                assertEq(maxSignatures, 16, "maxSignatures in data");
                assertEq(keyVersion, 1, "bumped epoch in data");
            }
        }
        assertTrue(found, "ShrincsVerifierSet emitted");
    }

    function test_setShrincsVerifier_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 0, MAX_SIG);
    }

    function test_setShrincsVerifier_revertsWhen_zeroCommitment() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.ZeroCommitment.selector);
        paymaster.setShrincsVerifier(bytes32(0), 0, MAX_SIG);
    }

    function test_setShrincsVerifier_revertsWhen_zeroMaxSignatures() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.ZeroMaxSignatures.selector);
        paymaster.setShrincsVerifier(NEW_COMMITMENT, 0, 0);
    }
}
