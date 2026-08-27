// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {SHRINCSTestSigner} from "@quip.network/hashsigs-solidity-0.2.0/test/helpers/SHRINCSTestSigner.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Tree retirement: a hash-based tree is one-time material for its lifetime. Every install
///      path must refuse a stateful or stateless tree this wallet has ever held — the same tree,
///      the same tree under a different budget, or a cycle back to an earlier tree — because the
///      per-epoch leaf bitmap would otherwise resurrect its consumed leaves.
contract ShrincsWallet_spentTrees is ShrincsWalletTest {
    address internal constant NEW_OWNER = address(0xA11CE);

    function setUp() public virtual override {
        super.setUp();
        // Mirror a factory-deployed wallet: `initialize` records the installed trees.
        wallet.harness_spendTrees(mainPk);
    }

    /*──────────────────────────── helpers ────────────────────────────*/

    function _statefulTreeId(bytes memory spk) internal pure returns (bytes32 pkSeed, bytes32 root) {
        assembly {
            pkSeed := mload(add(spk, 32))
            root := mload(add(spk, 64))
        }
    }

    function _treeId(bytes memory spk) internal pure returns (bytes32) {
        (bytes32 pkSeed, bytes32 root) = _statefulTreeId(spk);
        return keccak256(abi.encodePacked(pkSeed, root));
    }

    function _statelessId(SHRINCS.PublicKey memory pk) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(_toBytes32(pk.pkSeed), _toBytes32(pk.hypertreeRoot)));
    }

    /// @dev Stateful rotation target that recomputes to the installed bundle.
    function _sameStatefulTarget() internal view returns (SHRINCS.StatefulRotationTarget memory t) {
        t = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: mainPk.statefulPublicKey,
            publicKeyCommitment: mainPk.publicKeyCommitment
        });
    }

    /// @dev Same stateful tree, different declared budget: the commitment changes, the tree does not.
    function _sameTreeNewBudgetTarget()
        internal
        view
        returns (SHRINCS.StatefulRotationTarget memory t, bytes32 nextCommitment)
    {
        bytes memory spk = mainPk.statefulPublicKey;
        spk[67] = bytes1(uint8(spk[67]) + 1); // low byte of the trailing maxSignatures
        nextCommitment = SHRINCS.publicKeyCommitmentFromParts(spk, mainPk.pkSeed, mainPk.hypertreeRoot);
        t = SHRINCS.StatefulRotationTarget({
            statefulPublicKey: spk,
            publicKeyCommitment: abi.encodePacked(nextCommitment)
        });
    }

    /// @dev Full rotation target: fresh stateful tree, CURRENT stateless tree carried forward.
    function _freshStatefulSameStatelessTarget(bytes memory seed)
        internal
        view
        returns (SHRINCS.RotationTarget memory target)
    {
        (, SHRINCS.PublicKey memory pk, bool ok) = SHRINCSTestSigner.keygen(seed, MAX_SIG);
        require(ok, "keygen");
        bytes32 c = SHRINCS.publicKeyCommitmentFromParts(pk.statefulPublicKey, mainPk.pkSeed, mainPk.hypertreeRoot);
        target = SHRINCS.RotationTarget({
            statefulPublicKey: pk.statefulPublicKey,
            publicKeyCommitment: abi.encodePacked(c),
            pkSeed: mainPk.pkSeed,
            hypertreeRoot: mainPk.hypertreeRoot
        });
    }

    /// @dev Full rotation target from an entirely fresh keygen (both halves new).
    function _freshFullTarget(bytes memory seed)
        internal
        view
        returns (SHRINCS.RotationTarget memory target, SHRINCS.PublicKey memory pk)
    {
        bool ok;
        (, pk, ok) = SHRINCSTestSigner.keygen(seed, MAX_SIG);
        require(ok, "keygen");
        target = _rotationTargetOf(pk);
    }

    function _assertUnspent(SHRINCS.PublicKey memory pk) internal view {
        assertFalse(wallet.harness_isStatefulTreeSpent(_treeId(pk.statefulPublicKey)), "stateful unspent before");
        assertFalse(wallet.harness_isStatelessTreeSpent(_statelessId(pk)), "stateless unspent before");
    }

    function _assertSpent(SHRINCS.PublicKey memory pk) internal view {
        assertTrue(wallet.harness_isStatefulTreeSpent(_treeId(pk.statefulPublicKey)), "stateful spent after");
        assertTrue(wallet.harness_isStatelessTreeSpent(_statelessId(pk)), "stateless spent after");
    }

    function _rotationTargetOf(SHRINCS.PublicKey memory pk) internal pure returns (SHRINCS.RotationTarget memory) {
        return SHRINCS.RotationTarget({
            statefulPublicKey: pk.statefulPublicKey,
            publicKeyCommitment: pk.publicKeyCommitment,
            pkSeed: pk.pkSeed,
            hypertreeRoot: pk.hypertreeRoot
        });
    }

    function _rotateSig(bytes32 nextCommitment, uint32 slot) internal view returns (SHRINCS.Signature memory) {
        return _signStatefulAction(Codec.ACTION_ROTATE_KEY, Codec.rotateKeyPayloadHash(nextCommitment), slot);
    }

    /// @dev Rotates the stateful subkey to a fresh keygen and re-points the test signer at it, so
    ///      subsequent signatures come from the newly installed key.
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
        // Installed bundle = fresh stateful subkey under the original stateless half.
        mainKey = key;
        mainPk.statefulPublicKey = pk.statefulPublicKey;
        mainPk.publicKeyCommitment = abi.encodePacked(c);
        mainCommitment = c;
    }

    /*──────────────────────────── rotateKey ────────────────────────────*/

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

    function test_rotateKey_revertsWhen_sameStatefulTree() public {
        bytes32 id = _treeId(mainPk.statefulPublicKey);
        SHRINCS.Signature memory sig = _rotateSig(mainCommitment, 1);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, id));
        wallet.rotateKey(_mainPk(), sig, _sameStatefulTarget());
    }

    function test_rotateKey_revertsWhen_sameTreeDifferentBudget() public {
        (SHRINCS.StatefulRotationTarget memory t, bytes32 nextCommitment) = _sameTreeNewBudgetTarget();
        assertTrue(nextCommitment != mainCommitment, "budget changes the commitment");
        bytes32 id = _treeId(t.statefulPublicKey);
        SHRINCS.Signature memory sig = _rotateSig(nextCommitment, 1);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, id));
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
        bytes32 aCommitment = _toBytes32(treeA.publicKeyCommitment);
        SHRINCS.Signature memory sig = _rotateSig(aCommitment, 1); // signed by B
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(treeA.statefulPublicKey))
        );
        wallet.rotateKey(_mainPk(), sig, backToA);
    }

    function test_rotateKey_freshTreeStillSucceeds_andIsThenSpent() public {
        _rotateToFresh("spent-trees-fresh-1", 1);
        assertEq(wallet.keyVersion(), 1);
        // A second rotation to yet another fresh tree is fine...
        _rotateToFresh("spent-trees-fresh-2", 1);
        assertEq(wallet.keyVersion(), 2);
    }

    /*──────────────────────────── migrate ────────────────────────────*/

    function test_migrate_spendsBothInstalledTrees() public {
        (, SHRINCS.PublicKey memory fresh, bool ok) = SHRINCSTestSigner.keygen("migrate-spends", MAX_SIG);
        require(ok, "keygen");
        _assertUnspent(fresh);

        (bytes memory payload,) = _freshInitPayload("migrate-spends");
        wallet.harness_migrateInUpgradeContext(payload);

        _assertSpent(fresh);
    }

    function test_migrate_revertsWhen_currentBundle() public {
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.harness_migrateInUpgradeContext(_validInitPayload());
    }

    function test_migrate_revertsWhen_statelessTreeCarriedForward() public {
        // Fresh stateful tree, current stateless tree: migration is strictly fresh on both halves.
        (, SHRINCS.PublicKey memory fresh, bool ok) = SHRINCSTestSigner.keygen("migrate-carry-stateless", MAX_SIG);
        require(ok, "keygen");
        SHRINCS.PublicKey memory pk = fresh;
        pk.pkSeed = mainPk.pkSeed;
        pk.hypertreeRoot = mainPk.hypertreeRoot;
        bytes32 c = SHRINCS.publicKeyCommitmentFromParts(pk.statefulPublicKey, pk.pkSeed, pk.hypertreeRoot);
        pk.publicKeyCommitment = abi.encodePacked(c);
        bytes memory payload = _buildInitPayload(
            c, _toBytes32(pk.pkSeed), pk, HashSuite.HASH_SUITE_ID, erc1271Commitment, HashSuite.HASH_SUITE_ID
        );
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.harness_migrateInUpgradeContext(payload);
    }

    function test_migrate_revertsWhen_cyclingBackToEarlierBundle() public {
        (bytes memory fresh,) = _freshInitPayload("migrate-cycle-B");
        wallet.harness_migrateInUpgradeContext(fresh);
        assertEq(wallet.keyVersion(), 1);
        // Back to the original bundle: its stateful tree was spent at install.
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.harness_migrateInUpgradeContext(_validInitPayload());
    }

    /*──────────────────────────── recoverWallet ────────────────────────────*/

    function test_recoverWallet_spendsBothNextTrees() public {
        (SHRINCS.RotationTarget memory t, SHRINCS.PublicKey memory next) = _freshFullTarget("recover-spends");
        _assertUnspent(next);
        SPHINCSPlusC.Signature memory sig = _signFullRotation(t, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        vm.prank(OWNER);
        wallet.recoverWallet(_mainPk(), sig, t);
        assertEq(wallet.getShrincsPublicKeyCommitment(), _toBytes32(next.publicKeyCommitment), "recovered");
        _assertSpent(next);
    }

    function test_recoverWallet_revertsWhen_sameBundle() public {
        SHRINCS.RotationTarget memory same = _rotationTargetOf(mainPk);
        SPHINCSPlusC.Signature memory sig = _signFullRotation(same, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.recoverWallet(_mainPk(), sig, same);
    }

    function test_recoverWallet_revertsWhen_statelessTreeCarriedForward() public {
        SHRINCS.RotationTarget memory t = _freshStatefulSameStatelessTarget("recover-carry-stateless");
        SPHINCSPlusC.Signature memory sig = _signFullRotation(t, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.recoverWallet(_mainPk(), sig, t);
    }

    /*──────────────────────────── transferOwnership ────────────────────────────*/

    function test_transferOwnership_spendsBothNextTrees() public {
        (SHRINCS.RotationTarget memory t, SHRINCS.PublicKey memory next) = _freshFullTarget("transfer-spends");
        _assertUnspent(next);
        bytes32 c = _toBytes32(next.publicKeyCommitment);
        SPHINCSPlusC.Signature memory recoverySig = _signFullRotation(t, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        SHRINCS.Signature memory ownerSig =
            _signStatefulAction(Codec.ACTION_TRANSFER_OWNERSHIP, Codec.transferOwnershipPayloadHash(NEW_OWNER, c), 1);
        vm.prank(OWNER);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, t, NEW_OWNER);
        assertEq(wallet.owner(), NEW_OWNER, "handed over");
        _assertSpent(next);
    }

    function test_transferOwnership_revertsWhen_sameBundle() public {
        SHRINCS.RotationTarget memory same = _rotationTargetOf(mainPk);
        SPHINCSPlusC.Signature memory recoverySig = _signFullRotation(same, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        SHRINCS.Signature memory ownerSig = _signStatefulAction(
            Codec.ACTION_TRANSFER_OWNERSHIP, Codec.transferOwnershipPayloadHash(NEW_OWNER, mainCommitment), 1
        );
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, same, NEW_OWNER);
    }

    function test_transferOwnership_revertsWhen_statelessTreeCarriedForward() public {
        SHRINCS.RotationTarget memory t = _freshStatefulSameStatelessTarget("transfer-carry-stateless");
        bytes32 c = _toBytes32(t.publicKeyCommitment);
        SPHINCSPlusC.Signature memory recoverySig = _signFullRotation(t, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        SHRINCS.Signature memory ownerSig =
            _signStatefulAction(Codec.ACTION_TRANSFER_OWNERSHIP, Codec.transferOwnershipPayloadHash(NEW_OWNER, c), 1);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, t, NEW_OWNER);
    }
}
