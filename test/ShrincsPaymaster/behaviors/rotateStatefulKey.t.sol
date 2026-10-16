// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for `rotateStatefulKey` (owner-only FIAT rotation of the stateful subkey;
///      the stateless half is pinned from the verified current bundle and never rotates). Real key
///      material throughout: targets are fresh `SHRINCSTestSigner` keygens recombined with the
///      installed bundle's stateless half, exactly as the off-chain operator would build them.
contract ShrincsPaymaster_rotateStatefulKey is ShrincsPaymasterTest {
    /// @dev Builds a rotation target from a fresh keygen: the new stateful subkey combined with
    ///      the INSTALLED bundle's stateless half (mirrors the operator's off-chain construction).
    function _rotationTarget(bytes memory seed, uint32 maxSig)
        internal
        view
        returns (
            SHRINCS.SigningKey memory nextKey,
            SHRINCS.StatefulRotationTarget memory target,
            bytes32 nextCommitment
        )
    {
        SHRINCS.PublicKey memory freshPk;
        bool ok;
        (nextKey, freshPk, ok) = SHRINCSTestSigner.keygen(seed, maxSig);
        require(ok, "rotation keygen");
        nextCommitment = SHRINCS.publicKeyCommitmentFromParts(
            freshPk.statefulPublicKey,
            verifierPk.pkSeed,
            verifierPk.hypertreeRoot
        );
        target = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: freshPk.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(nextCommitment)
        });
    }

    /// @dev The full public-key bundle installed AFTER rotating to `target`: new stateful subkey,
    ///      original stateless half.
    function _rotatedBundle(SHRINCS.StatefulRotationTarget memory target, bytes32 nextCommitment)
        internal
        view
        returns (SHRINCS.PublicKey memory pk)
    {
        pk.statefulPublicKey = target.statefulPublicKey;
        pk.publicKeyCommitment = abi.encodePacked(nextCommitment);
        pk.pkSeed = verifierPk.pkSeed;
        pk.hypertreeRoot = verifierPk.hypertreeRoot;
    }

    function test_rotateStatefulKey_rotatesAndBumpsEpoch() public {
        (, SHRINCS.StatefulRotationTarget memory target, bytes32 nextCommitment) =
            _rotationTarget("rotate-next-1", 16);

        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, target);

        (
            bytes32 commitment,
            ,
            uint256 keyVersion,
            uint32 maxSignatures,
            uint32 statefulLeavesUsed
        ) = paymaster.getShrincsVerifier();
        assertEq(commitment, nextCommitment, "commitment rotated");
        assertEq(keyVersion, 1, "epoch bumped");
        assertEq(maxSignatures, 16, "budget decoded from the new subkey");
        assertEq(statefulLeavesUsed, 0, "counter reset");
    }

    /// @dev The installed commitment binds the ORIGINAL stateless half, not the fresh keygen's
    ///      own — the stateless side never rotates on this path.
    function test_rotateStatefulKey_carriesStatelessHalfForward() public {
        (, SHRINCS.PublicKey memory freshPk, bool ok) =
            SHRINCSTestSigner.keygen("rotate-next-stateless", MAX_SIG);
        require(ok, "keygen");
        bytes32 nextCommitment = SHRINCS.publicKeyCommitmentFromParts(
            freshPk.statefulPublicKey,
            verifierPk.pkSeed,
            verifierPk.hypertreeRoot
        );
        SHRINCS.StatefulRotationTarget memory target = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: freshPk.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(nextCommitment)
        });

        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, target);

        (bytes32 installed,,,,) = paymaster.getShrincsVerifier();
        assertEq(installed, nextCommitment, "recomputed-from-parts commitment installed");
        assertTrue(
            installed != _toBytes32(freshPk.publicKeyCommitment),
            "fresh keygen's own full-bundle commitment NOT installed"
        );
    }

    function test_rotateStatefulKey_freshBitmapNamespace() public {
        paymaster.harness_markLeafUsed(1);
        assertTrue(paymaster.isStatefulLeafUsed(1), "used under epoch 0");

        (, SHRINCS.StatefulRotationTarget memory target,) =
            _rotationTarget("rotate-next-2", MAX_SIG);
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, target);
        assertFalse(paymaster.isStatefulLeafUsed(1), "fresh namespace under epoch 1");
    }

    /// @dev Epoch is MONOTONIC across successive rotations; each rotation's `currentPublicKey` is
    ///      the previously installed (rotated) bundle — the stateless half stays constant.
    function test_rotateStatefulKey_epochMonotonicAcrossRotations() public {
        (, SHRINCS.StatefulRotationTarget memory target1, bytes32 commitment1) =
            _rotationTarget("rotate-next-3a", MAX_SIG);
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, target1);
        (,, uint256 epoch1,,) = paymaster.getShrincsVerifier();
        assertEq(epoch1, 1, "first rotation -> epoch 1");

        paymaster.harness_markLeafUsed(1);
        assertTrue(paymaster.isStatefulLeafUsed(1), "used under epoch 1");

        (, SHRINCS.StatefulRotationTarget memory target2,) =
            _rotationTarget("rotate-next-3b", MAX_SIG);
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(_rotatedBundle(target1, commitment1), target2);
        (,, uint256 epoch2,,) = paymaster.getShrincsVerifier();
        assertEq(epoch2, 2, "second rotation -> epoch 2 (never resets)");
        assertFalse(
            paymaster.isStatefulLeafUsed(1),
            "epoch 1's consumed leaf is invisible under epoch 2"
        );
    }

    /// @dev The used counter is reset on rotation even after real consumption.
    function test_rotateStatefulKey_resetsCounterAfterUse() public {
        paymaster.harness_markLeafUsed(1);
        paymaster.harness_markLeafUsed(2);
        assertEq(paymaster.statefulLeavesUsed(), 2, "counter advanced");

        (, SHRINCS.StatefulRotationTarget memory target,) =
            _rotationTarget("rotate-next-4", MAX_SIG);
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, target);
        assertEq(paymaster.statefulLeavesUsed(), 0, "counter reset on rotation");
        assertEq(paymaster.remainingStatefulSignatures(), MAX_SIG);
    }

    function test_rotateStatefulKey_emitsKeyRotated() public {
        (, SHRINCS.StatefulRotationTarget memory target, bytes32 nextCommitment) =
            _rotationTarget("rotate-next-5", 16);

        vm.expectEmit(true, true, false, true, address(paymaster));
        emit IShrincsPaymaster.KeyRotated(verifierCommitment, nextCommitment, 1, 16);
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, target);
    }

    /// @dev End-to-end: after rotation, a sponsorship signed by the NEW stateful key (under the
    ///      rotated bundle and epoch 1) validates and consumes an epoch-1 leaf.
    function test_rotateStatefulKey_sponsorshipUnderNewKeyAccepted() public {
        (
            SHRINCS.SigningKey memory nextKey,
            SHRINCS.StatefulRotationTarget memory target,
            bytes32 nextCommitment
        ) = _rotationTarget("rotate-next-6", MAX_SIG);
        SHRINCS.PublicKey memory rotatedPk = _rotatedBundle(target, nextCommitment);

        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, target);

        // Re-point the base-test signing state at the rotated key so the standard sponsorship
        // helpers sign under the new commitment/epoch.
        verifierKey = nextKey;
        verifierPk = rotatedPk;
        verifierCommitment = nextCommitment;

        (PackedUserOperation memory op, uint32 leaf) = _sponsorUserOp(0);
        (, uint256 validationData) = _validate(op);
        assertEq(validationData, 0, "sponsorship under the rotated key accepted");
        assertTrue(paymaster.isStatefulLeafUsed(leaf), "epoch-1 leaf consumed");
    }

    /// @dev After rotation the OLD key's sponsorships are rejected: the old bundle no longer
    ///      matches the installed commitment.
    function test_rotateStatefulKey_sponsorshipUnderOldKeyRejected() public {
        // Sign under the OLD key/epoch FIRST (the binding context reads the live epoch 0).
        (PackedUserOperation memory op,) = _sponsorUserOp(0);

        (, SHRINCS.StatefulRotationTarget memory target,) =
            _rotationTarget("rotate-next-7", MAX_SIG);
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, target);

        (, uint256 validationData) = _validate(op);
        assertEq(validationData, 1, "old-key sponsorship rejected after rotation");
    }

    function test_rotateStatefulKey_revertsWhen_notOwner() public {
        (, SHRINCS.StatefulRotationTarget memory target,) =
            _rotationTarget("rotate-next-8", MAX_SIG);
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.rotateStatefulKey(verifierPk, target);
    }

    /// @dev A `currentPublicKey` bundle that is not the installed one fails the commitment pin —
    ///      its stateless half cannot be trusted to carry forward.
    function test_rotateStatefulKey_revertsWhen_currentBundleMismatch() public {
        (, SHRINCS.PublicKey memory strangerPk, bool ok) =
            SHRINCSTestSigner.keygen("not-the-installed-key", MAX_SIG);
        require(ok, "keygen");
        (, SHRINCS.StatefulRotationTarget memory target,) =
            _rotationTarget("rotate-next-9", MAX_SIG);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.CommitmentMismatch.selector);
        paymaster.rotateStatefulKey(strangerPk, target);
    }

    /// @dev The fiat path's end-to-end guard: a declared target commitment that does not match the
    ///      recomputed one is rejected (no signature proves the operator controls the new key, so a
    ///      mistyped commitment must never install).
    function test_rotateStatefulKey_revertsWhen_declaredCommitmentMismatch() public {
        (, SHRINCS.StatefulRotationTarget memory target,) =
            _rotationTarget("rotate-next-10", MAX_SIG);
        target.publicKeyCommitment = abi.encodePacked(keccak256("fat-fingered-commitment"));

        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.CommitmentMismatch.selector);
        paymaster.rotateStatefulKey(verifierPk, target);
    }

    function test_rotateStatefulKey_revertsWhen_badTargetLength() public {
        (, SHRINCS.StatefulRotationTarget memory target,) =
            _rotationTarget("rotate-next-11", MAX_SIG);
        target.statefulPublicKey = hex"deadbeef"; // != STATEFUL_PUBLIC_KEY_BYTES

        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.CommitmentMismatch.selector);
        paymaster.rotateStatefulKey(verifierPk, target);
    }

    /// @dev A structurally valid subkey encoding a zero leaf budget can never authorize anything.
    function test_rotateStatefulKey_revertsWhen_zeroMaxSignatures() public {
        (, SHRINCS.StatefulRotationTarget memory target,) =
            _rotationTarget("rotate-next-12", MAX_SIG);
        // Encoded stateful public key layout: pkSeed(32) | root(32) | maxSignatures(4).
        // Zero the budget bytes in place.
        for (uint256 i = 64; i < SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES; ++i) {
            target.statefulPublicKey[i] = bytes1(0);
        }

        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.ZeroMaxSignatures.selector);
        paymaster.rotateStatefulKey(verifierPk, target);
    }

    /*──────────────────── spent-tree tracking ────────────────────*/

    function test_rotateStatefulKey_spendsNextStatefulTree() public {
        (, SHRINCS.StatefulRotationTarget memory t,) = _rotationTarget("rotate-spends", 16);
        bytes32 id = _treeId(t.statefulPublicKey);
        assertFalse(paymaster.harness_isStatefulTreeSpent(id), "unspent before");
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, t);
        assertTrue(paymaster.harness_isStatefulTreeSpent(id), "rotateStatefulKey spends the next tree");
        assertTrue(paymaster.harness_isStatefulTreeSpent(_treeId(verifierPk.statefulPublicKey)), "previous stays spent");
    }

    function test_rotateStatefulKey_freshTreesKeepWorking() public {
        (, SHRINCS.StatefulRotationTarget memory t1, bytes32 c1) = _rotationTarget("spent-fresh-1", 16);
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, t1);
        (, SHRINCS.StatefulRotationTarget memory t2,) = _rotationTarget("spent-fresh-2", 16);
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(_rotatedBundle(t1, c1), t2);
        (, , uint256 keyVersion, , ) = paymaster.getShrincsVerifier();
        assertEq(keyVersion, 2);
    }

    function test_rotateStatefulKey_revertsWhen_sameStatefulTree() public {
        SHRINCS.StatefulRotationTarget memory same = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: verifierPk.statefulPublicKey,
            publicKeyCommitment: verifierPk.publicKeyCommitment
        });
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsPaymaster.StatefulTreeSpent.selector, _treeId(verifierPk.statefulPublicKey))
        );
        paymaster.rotateStatefulKey(verifierPk, same);
    }

    function test_rotateStatefulKey_revertsWhen_sameTreeDifferentBudget() public {
        bytes memory spk = verifierPk.statefulPublicKey;
        spk[67] = bytes1(uint8(spk[67]) + 1); // low byte of the trailing maxSignatures
        bytes32 c = SHRINCS.publicKeyCommitmentFromParts(spk, verifierPk.pkSeed, verifierPk.hypertreeRoot);
        assertTrue(c != _toBytes32(verifierPk.publicKeyCommitment), "budget changes the commitment");
        SHRINCS.StatefulRotationTarget memory t =
            SHRINCS.StatefulRotationTarget({statefulPublicKey: spk, publicKeyCommitment: abi.encodePacked(c)});
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsPaymaster.StatefulTreeSpent.selector, _treeId(spk)));
        paymaster.rotateStatefulKey(verifierPk, t);
    }

    function test_rotateStatefulKey_revertsWhen_cyclingBackToEarlierTree() public {
        (, SHRINCS.StatefulRotationTarget memory targetB, bytes32 commitmentB) = _rotationTarget("spent-B", 16);
        vm.prank(OWNER);
        paymaster.rotateStatefulKey(verifierPk, targetB);
        SHRINCS.PublicKey memory bundleB = _rotatedBundle(targetB, commitmentB);

        // B -> A: the initial tree was recorded at `initialize`.
        SHRINCS.StatefulRotationTarget memory backToA = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: verifierPk.statefulPublicKey,
            publicKeyCommitment: verifierPk.publicKeyCommitment
        });
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsPaymaster.StatefulTreeSpent.selector, _treeId(verifierPk.statefulPublicKey))
        );
        paymaster.rotateStatefulKey(bundleB, backToA);
    }
}
