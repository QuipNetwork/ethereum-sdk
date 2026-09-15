// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for stateful `rotateKey`. The input-validation reverts (target length /
///      zero maxSignatures), leaf guards, `InvalidSignature`, and the live-signed success path
///      (new stateful subkey, reused stateless root, `keyVersion++`, nonce unchanged) are all
///      exercised.
contract ShrincsWallet_rotateKey is ShrincsWalletTest {
    /// @dev A structurally-valid 68-byte stateful rotation target (freshly generated subkey).
    function _validTarget() internal view returns (SHRINCS.StatefulRotationTarget memory t) {
        (t,) = _makeStatefulRotationTarget("rotate-key-next-stateful");
    }

    function test_rotateKey_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), _validTarget());
    }

    function test_rotateKey_revertsWhen_badStatefulKeyLength() public {
        SHRINCS.StatefulRotationTarget memory t;
        t.statefulPublicKey = hex"00112233"; // not 68 bytes
        t.publicKeyCommitment = abi.encodePacked(bytes32(0));

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), t);
    }

    function test_rotateKey_revertsWhen_zeroMaxSignatures() public {
        SHRINCS.StatefulRotationTarget memory t = _validTarget();
        bytes memory spk = t.statefulPublicKey;
        spk[64] = 0;
        spk[65] = 0;
        spk[66] = 0;
        spk[67] = 0; // zero the trailing maxSignatures
        t.statefulPublicKey = spk;

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ZeroMaxSignatures.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), t);
    }

    function test_rotateKey_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(0), _validTarget());
    }

    function test_rotateKey_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.rotateKey(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), _validTarget());
    }

    function test_rotateKey_revertsWhen_invalidSignature() public {
        SHRINCS.Signature memory sig = _wrongContextStatefulSig();
        SHRINCS.StatefulRotationTarget memory target = _validTarget();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.rotateKey(_mainPk(), sig, target);
    }

    function test_rotateKey_succeeds() public {
        (SHRINCS.StatefulRotationTarget memory t, bytes32 nextCommitment) =
            _makeStatefulRotationTarget("rotate-key-next-stateful");
        SHRINCS.Signature memory sig =
            _signStatefulAction(Codec.ACTION_ROTATE_KEY, Codec.rotateKeyPayloadHash(nextCommitment), 1);
        uint256 nonceBefore = wallet.actionNonce();
        vm.prank(OWNER);
        wallet.rotateKey(_mainPk(), sig, t);
        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommitment, "new stateful subkey installed");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
        assertEq(wallet.actionNonce(), nonceBefore + 1, "rotateKey advances the action nonce (+1 via the shared core)");
        assertEq(wallet.statefulLeavesUsed(), 0, "fresh epoch counter");
    }

    /*──────────────────── spent-tree tracking ────────────────────*/

    function _rotateSig(bytes32 nextCommitment, uint32 slot) internal view returns (SHRINCS.Signature memory) {
        return _signStatefulAction(Codec.ACTION_ROTATE_KEY, Codec.rotateKeyPayloadHash(nextCommitment), slot);
    }

    /// @dev Rotates the stateful subkey to a fresh keygen and re-points the test signer at it.
    function _rotateToFresh(bytes memory seed, uint32 slot) internal returns (SHRINCS.PublicKey memory prevPk) {
        prevPk = mainPk;
        (SHRINCS.SigningKey memory key, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen(seed, MAX_SIG);
        require(ok, "keygen");
        bytes32 c = SHRINCS.publicKeyCommitmentFromParts(pk.statefulPublicKey, mainPk.pkSeed, mainPk.hypertreeRoot);
        SHRINCS.StatefulRotationTarget memory t = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: pk.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(c)
        });
        SHRINCS.Signature memory sig = _rotateSig(c, slot);
        vm.prank(OWNER);
        wallet.rotateKey(_mainPk(), sig, t);
        assertEq(wallet.getShrincsPublicKeyCommitment(), c, "rotated");
        mainKey = key;
        mainPk.statefulPublicKey = pk.statefulPublicKey;
        mainPk.publicKeyCommitment = abi.encodePacked(c);
        mainCommitment = c;
    }

    function test_rotateKey_spendsNextStatefulTree() public {
        (, SHRINCS.PublicKey memory next, bool ok) = SHRINCSTestSigner.keygen("rotate-spends", MAX_SIG);
        require(ok, "keygen");
        bytes32 id = _treeId(next.statefulPublicKey);
        assertFalse(wallet.harness_isStatefulTreeSpent(id), "unspent before");

        _rotateToFresh("rotate-spends", 1);

        assertTrue(wallet.harness_isStatefulTreeSpent(id), "rotateKey spends the next stateful tree");
        // The stateless half is carried forward, so it stays spent from install.
        assertTrue(wallet.harness_isStatelessTreeSpent(_statelessId(mainPk)), "stateless still spent");
    }

    function test_rotateKey_freshTreesKeepWorking() public {
        _rotateToFresh("spent-trees-fresh-1", 1);
        assertEq(wallet.keyVersion(), 1);
        _rotateToFresh("spent-trees-fresh-2", 1);
        assertEq(wallet.keyVersion(), 2);
    }

    function test_rotateKey_revertsWhen_sameStatefulTree() public {
        bytes32 id = _treeId(mainPk.statefulPublicKey);
        SHRINCS.StatefulRotationTarget memory same = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: mainPk.statefulPublicKey,
            publicKeyCommitment: mainPk.publicKeyCommitment
        });
        SHRINCS.Signature memory sig = _rotateSig(mainCommitment, 1);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, id));
        wallet.rotateKey(_mainPk(), sig, same);
    }

    function test_rotateKey_revertsWhen_sameTreeDifferentBudget() public {
        // Same stateful tree, different declared budget: the commitment changes, the tree does not.
        bytes memory spk = mainPk.statefulPublicKey;
        spk[67] = bytes1(uint8(spk[67]) + 1); // low byte of the trailing maxSignatures
        bytes32 nextCommitment = SHRINCS.publicKeyCommitmentFromParts(spk, mainPk.pkSeed, mainPk.hypertreeRoot);
        assertTrue(nextCommitment != mainCommitment, "budget changes the commitment");
        SHRINCS.StatefulRotationTarget memory t = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: spk,
            publicKeyCommitment: abi.encodePacked(nextCommitment)
        });
        SHRINCS.Signature memory sig = _rotateSig(nextCommitment, 1);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(spk)));
        wallet.rotateKey(_mainPk(), sig, t);
    }

    /// @dev Regression (audit): the dedicated ERC-1271 bundle's STATEFUL tree is registered at
    ///      install too — rotating the main key onto it is refused.
    function test_rotateKey_revertsWhen_erc1271StatefulTreeReused() public {
        bytes32 c = SHRINCS.publicKeyCommitmentFromParts(erc1271Pk.statefulPublicKey, mainPk.pkSeed, mainPk.hypertreeRoot);
        SHRINCS.StatefulRotationTarget memory t = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: erc1271Pk.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(c)
        });
        SHRINCS.Signature memory sig = _rotateSig(c, 1);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(erc1271Pk.statefulPublicKey))
        );
        wallet.rotateKey(_mainPk(), sig, t);
    }

    function test_rotateKey_revertsWhen_cyclingBackToEarlierTree() public {
        // Consume a leaf under tree A, rotate A -> B, then try B -> A.
        wallet.harness_markLeafUsed(SIGN_BASE + 3);
        SHRINCS.PublicKey memory treeA = _rotateToFresh("spent-trees-B", 1);
        assertEq(wallet.keyVersion(), 1);

        SHRINCS.StatefulRotationTarget memory backToA = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: treeA.statefulPublicKey,
            publicKeyCommitment: treeA.publicKeyCommitment
        });
        SHRINCS.Signature memory sig = _rotateSig(_toBytes32(treeA.publicKeyCommitment), 1); // signed by B
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(treeA.statefulPublicKey))
        );
        wallet.rotateKey(_mainPk(), sig, backToA);
    }
}
