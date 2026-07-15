// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `markLeavesUsed` (surgical batch leaf revocation). The headline
///      property under test is the deliberate nonce carve-out: the authorizing signature is
///      consumed WITHOUT advancing the action nonce, so revocation kills exactly the listed
///      leaves while outstanding signed material at other leaves stays valid. Skip semantics
///      (races/duplicates/auth-leaf), the out-of-range and empty-array reverts, gates, and
///      epoch scoping are each exercised with live-signed revocation signatures.
contract ShrincsWallet_markLeavesUsed is ShrincsWalletTest {
    /// @dev Independent mirror of the wallet's `leavesHash` preimage: one 32-byte word per
    ///      leaf index, in order (the wallet builds it via the EfficientHashLib word buffer).
    function _leavesHash(uint32[] memory leaves) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i = 0; i < leaves.length; i++) {
            packed = abi.encodePacked(packed, bytes32(uint256(leaves[i])));
        }
        return keccak256(packed);
    }

    /// @dev Signs the wallet's MARK_LEAVES_USED context over the exact target array at `authLeaf`.
    function _markSig(uint32[] memory leaves, uint32 authLeaf)
        internal
        view
        returns (SHRINCS.Signature memory)
    {
        bytes32 payloadHash = Codec.markLeavesUsedPayloadHash(_leavesHash(leaves));
        return _signStatefulAction(Codec.ACTION_MARK_LEAVES_USED, payloadHash, authLeaf);
    }

    function _targets(uint32 a) internal pure returns (uint32[] memory leaves) {
        leaves = new uint32[](1);
        leaves[0] = a;
    }

    function _targets(uint32 a, uint32 b) internal pure returns (uint32[] memory leaves) {
        leaves = new uint32[](2);
        leaves[0] = a;
        leaves[1] = b;
    }

    /* ─────────────────────────────── GATES / REVERTS ─────────────────────────────── */

    function test_markLeavesUsed_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.markLeavesUsed(_mainPk(), _statefulSigWithLeaf(1), _targets(2));
    }

    function test_markLeavesUsed_revertsWhen_emptyLeaves() public {
        // The empty guard runs before signature verification — no leaf is burned.
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.EmptyLeaves.selector);
        wallet.markLeavesUsed(_mainPk(), _statefulSigWithLeaf(1), new uint32[](0));
        assertEq(wallet.statefulLeavesUsed(), 0, "nothing consumed on empty-array revert");
    }

    function test_markLeavesUsed_revertsWhen_authLeafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.markLeavesUsed(_mainPk(), _statefulSigWithLeaf(0), _targets(2));
    }

    function test_markLeavesUsed_revertsWhen_authLeafAlreadyUsed() public {
        wallet.harness_markLeafUsed(1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.markLeavesUsed(_mainPk(), _statefulSigWithLeaf(1), _targets(2));
    }

    function test_markLeavesUsed_revertsWhen_invalidSignature() public {
        SHRINCS.Signature memory sig = _wrongContextStatefulSig();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.markLeavesUsed(_mainPk(), sig, _targets(2));
        assertFalse(wallet.isStatefulLeafUsed(2), "target untouched on invalid signature");
    }

    function test_markLeavesUsed_revertsWhen_signatureBindsWrongArray() public {
        // A signature over [2] must not authorize revoking [2,3]: the payload commits to the
        // exact target array, so a submitter can neither add nor drop targets.
        SHRINCS.Signature memory sig = _markSig(_targets(2), 1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.markLeavesUsed(_mainPk(), sig, _targets(2, 3));
    }

    function test_markLeavesUsed_revertsWhen_staleNonceSignature() public {
        // The revocation binds the live nonce like every action; a consumed action elsewhere
        // supersedes a pending revocation signature.
        SHRINCS.Signature memory sig = _markSig(_targets(2), 1);
        wallet.harness_setNonce(wallet.actionNonce() + 1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.markLeavesUsed(_mainPk(), sig, _targets(2));
    }

    function test_markLeavesUsed_revertsWhen_wrongEpochSignature() public {
        // A revocation signed under epoch E is invalid after any rotation (context binds
        // keyVersion; the new epoch's bitmap namespace is empty anyway).
        SHRINCS.Signature memory sig = _markSig(_targets(2), 1);
        wallet.harness_setKeyVersion(1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.markLeavesUsed(_mainPk(), sig, _targets(2));
    }

    function test_markLeavesUsed_revertsWhen_targetLeafZero() public {
        // Out-of-range targets are a client bug, not a race: the whole batch reverts (which
        // also rolls back the authorizing-leaf consumption).
        SHRINCS.Signature memory sig = _markSig(_targets(0), 1);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.LeafOutOfRange.selector, 0));
        wallet.markLeavesUsed(_mainPk(), sig, _targets(0));
        assertFalse(wallet.isStatefulLeafUsed(1), "auth-leaf consumption rolled back");
    }

    function test_markLeavesUsed_revertsWhen_targetLeafOverBudget() public {
        uint32 over = MAX_SIG + 1;
        SHRINCS.Signature memory sig = _markSig(_targets(2, over), 1);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.LeafOutOfRange.selector, over));
        wallet.markLeavesUsed(_mainPk(), sig, _targets(2, over));
    }

    /* ─────────────────────────────── SUCCESS / SKIPS ─────────────────────────────── */

    function test_markLeavesUsed_succeeds_nonceUnchanged() public {
        uint32[] memory leaves = _targets(2, 3);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);
        uint256 nonceBefore = wallet.actionNonce();

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.StatefulSignatureVerified(1, 0);
        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.LeafRevoked(2, 0);
        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.LeafRevoked(3, 0);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);

        assertTrue(wallet.isStatefulLeafUsed(1), "authorizing leaf consumed");
        assertTrue(wallet.isStatefulLeafUsed(2), "target 2 revoked");
        assertTrue(wallet.isStatefulLeafUsed(3), "target 3 revoked");
        assertEq(wallet.statefulLeavesUsed(), 3, "auth + 2 targets counted");
        assertEq(
            wallet.actionNonce(),
            nonceBefore,
            "surgical carve-out: revocation must NOT advance the action nonce"
        );
    }

    function test_markLeavesUsed_replayRejected() public {
        // The consumed authorizing leaf — not the nonce — is what blocks replaying the call.
        uint32[] memory leaves = _targets(2);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);
    }

    function test_markLeavesUsed_skipsAlreadyUsedTarget() public {
        wallet.harness_markLeafUsed(2);
        uint32[] memory leaves = _targets(2, 3);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.LeafRevocationSkipped(2, 0);
        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.LeafRevoked(3, 0);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);

        // 1 pre-marked + 1 auth + 1 fresh target; the skip must not double-count leaf 2.
        assertEq(wallet.statefulLeavesUsed(), 3, "skip does not double-count");
    }

    function test_markLeavesUsed_skipsDuplicateInArray() public {
        uint32[] memory leaves = _targets(2, 2);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.LeafRevoked(2, 0);
        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.LeafRevocationSkipped(2, 0);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);

        assertEq(wallet.statefulLeavesUsed(), 2, "auth + one unique target");
    }

    function test_markLeavesUsed_skipsAuthLeafInArray() public {
        // The authorizing leaf was just consumed by the verify, so listing it degrades to a skip.
        uint32[] memory leaves = _targets(1, 2);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.LeafRevocationSkipped(1, 0);
        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.LeafRevoked(2, 0);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);

        assertEq(wallet.statefulLeavesUsed(), 2, "auth + one fresh target");
    }

    function test_markLeavesUsed_acceptsBoundaryLeafMaxSignatures() public {
        // leaf == maxSignatures is the last in-range index, not out-of-range.
        uint32[] memory leaves = _targets(MAX_SIG);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);
        assertTrue(wallet.isStatefulLeafUsed(MAX_SIG), "boundary leaf revoked");
    }

    /* ─────────────────────────── SURGICAL PROPERTY (E2E) ─────────────────────────── */

    function test_markLeavesUsed_preservesOutstandingUserOp() public {
        // Sign a userOp at leaf 5, THEN revoke an unrelated leaf. Because revocation does not
        // advance the nonce, the pre-signed op must still validate and land afterward — the
        // property the carve-out exists to provide.
        bytes32 userOpHash = keccak256("outstanding-user-op");
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(_userOpBlob(_signErc4337(userOpHash, 5), userOpHash));

        uint32[] memory leaves = _targets(3);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);

        assertEq(wallet.exposed_validateSignature(op, userOpHash), 0, "outstanding op survives revocation");
        assertTrue(wallet.isStatefulLeafUsed(5), "op's leaf consumed normally afterward");
        assertEq(wallet.actionNonce(), 1, "only the landed op advanced the nonce");
    }

    function test_markLeavesUsed_revokedLeafRejectsPendingUserOp() public {
        // The inverse direction: revoking the op's own leaf kills exactly that op.
        bytes32 userOpHash = keccak256("doomed-user-op");
        ERC4337.PackedUserOperation memory op =
            _makeUserOp(_userOpBlob(_signErc4337(userOpHash, 5), userOpHash));

        uint32[] memory leaves = _targets(5);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);

        assertEq(wallet.exposed_validateSignature(op, userOpHash), 1, "revoked leaf must reject the op");
        assertEq(wallet.statefulLeavesUsed(), 2, "rejection consumes nothing further");
    }

    function test_markLeavesUsed_revokedLeafRejectsDirectExecute() public {
        // Same property on the direct signed path.
        address target = address(0xBEEF);
        bytes32 payloadHash = Codec.executePayloadHash(target, 0, keccak256(""), 0);
        SHRINCS.Signature memory executeSig =
            _signStatefulAction(Codec.ACTION_EXECUTE, payloadHash, 4);

        uint32[] memory leaves = _targets(4);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.execute(_mainPk(), executeSig, target, 0, "", 0);
    }

    /* ─────────────────────────────── EPOCH SCOPING ─────────────────────────────── */

    function test_markLeavesUsed_rotationClearsRevocations() public {
        uint32[] memory leaves = _targets(2, 3);
        SHRINCS.Signature memory sig = _markSig(leaves, 1);
        vm.prank(OWNER);
        wallet.markLeavesUsed(_mainPk(), sig, leaves);
        assertTrue(wallet.isStatefulLeafUsed(2), "revoked in epoch 0");

        // Rotate: the new epoch's bitmap namespace is fresh — revocations do not leak across.
        (SHRINCS.StatefulRotationTarget memory t, bytes32 nextCommitment) =
            _makeStatefulRotationTarget("mark-leaves-rotation");
        SHRINCS.Signature memory rotateSig =
            _signStatefulAction(Codec.ACTION_ROTATE_KEY, Codec.rotateKeyPayloadHash(nextCommitment), 4);
        vm.prank(OWNER);
        wallet.rotateKey(_mainPk(), rotateSig, t);

        assertEq(wallet.keyVersion(), 1, "epoch bumped");
        assertFalse(wallet.isStatefulLeafUsed(2), "epoch-0 revocation invisible in epoch 1");
        assertEq(wallet.statefulLeavesUsed(), 0, "fresh epoch counter");
    }
}
