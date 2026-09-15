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
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `setErc1271Key`. Reverts plus the success path (commitment +
///      suite updated, `Erc1271KeySet`, both trees of the new bundle spent) are all exercised.
contract ShrincsWallet_setErc1271Key is ShrincsWalletTest {
    uint32 internal constant SUITE = HashSuite.HASH_SUITE_ID;

    SHRINCS.PublicKey internal newPk;
    bytes32 internal newCommitment;

    function setUp() public override {
        super.setUp();
        newPk = _freshErc1271Pk("set-erc1271-new");
        newCommitment = _commitment32(newPk);
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertTrue(newCommitment != bytes32(0), "fresh 1271 bundle derived");
        assertTrue(newCommitment != erc1271Commitment, "replacement differs from the installed key");
        assertFalse(
            wallet.harness_isStatefulTreeSpent(_treeId(newPk.statefulPublicKey)),
            "replacement trees unspent"
        );
    }

    function _sigFor(SHRINCS.PublicKey memory pk) internal view returns (SHRINCS.Signature memory) {
        return _signStatefulAction(
            Codec.ACTION_SET_ERC1271_KEY, Codec.setErc1271KeyPayloadHash(_commitment32(pk), SUITE), 1
        );
    }

    function test_setErc1271Key_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), newPk, SUITE);
    }

    function test_setErc1271Key_revertsWhen_invalidBundle() public {
        SHRINCS.PublicKey memory bad = newPk;
        bad.publicKeyCommitment = abi.encodePacked(keccak256("corrupted-erc1271-commitment"));
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), bad, SUITE);
    }

    function test_setErc1271Key_revertsWhen_unsupportedHashSuite() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.UnsupportedHashSuite.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), newPk, SHRINCS.HASH_SUITE_UNSUPPORTED);
    }

    function test_setErc1271Key_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(0), newPk, SUITE);
    }

    function test_setErc1271Key_revertsWhen_leafOverBudget() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1), newPk, SUITE);
    }

    function test_setErc1271Key_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.setErc1271Key(_mainPk(), _statefulSigWithLeaf(SIGN_BASE + 1), newPk, SUITE);
    }

    function test_setErc1271Key_revertsWhen_invalidSignature() public {
        SHRINCS.Signature memory sig = _wrongContextStatefulSig();
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.setErc1271Key(_mainPk(), sig, newPk, SUITE);
    }

    /*──────────────── isolation from the recovery authority (audit regression) ────────────────*/

    /// @dev The main key itself may never become the ERC-1271 key: its trees were spent at
    ///      install. Rejected BEFORE signature verification — no leaf is consumed.
    function test_setErc1271Key_revertsWhen_bundleIsMainKey() public {
        SHRINCS.Signature memory sig = _sigFor(mainPk);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.setErc1271Key(_mainPk(), sig, _mainPk(), SUITE);
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "no leaf consumed on registry revert");
    }

    /// @dev A fresh stateful subkey over the main key's stateless root: a brand-new commitment
    ///      that a commitment-equality check would accept. Rejected on the stateless registry.
    function test_setErc1271Key_revertsWhen_bundleSharesMainStatelessRoot() public {
        SHRINCS.PublicKey memory epk = _bundleSharingStatelessRoot("set-1271-shares-root", mainPk);
        SHRINCS.Signature memory sig = _sigFor(epk);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.setErc1271Key(_mainPk(), sig, epk, SUITE);
    }

    /// @dev The other half-axis: a 1271 bundle with a FRESH stateless root but the main key's
    ///      STATEFUL subkey — rejected on the stateful registry (halves are guarded independently).
    function test_setErc1271Key_revertsWhen_bundleSharesMainStatefulTree() public {
        SHRINCS.PublicKey memory epk = _freshErc1271Pk("set-1271-main-stateful");
        epk.statefulPublicKey = mainPk.statefulPublicKey;
        epk.publicKeyCommitment = abi.encodePacked(
            SHRINCS.publicKeyCommitmentFromParts(epk.statefulPublicKey, epk.pkSeed, epk.hypertreeRoot)
        );
        SHRINCS.Signature memory sig = _sigFor(epk);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.setErc1271Key(_mainPk(), sig, epk, SUITE);
    }

    /// @dev Re-setting the CURRENT ERC-1271 bundle is a re-install of held trees.
    function test_setErc1271Key_revertsWhen_bundleIsCurrentErc1271Key() public {
        SHRINCS.Signature memory sig = _sigFor(erc1271Pk);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(erc1271Pk.statefulPublicKey))
        );
        wallet.setErc1271Key(_mainPk(), sig, erc1271Pk, SUITE);
    }

    /// @dev Once rotated away, a former ERC-1271 bundle can never come back.
    function test_setErc1271Key_revertsWhen_bundleIsFormerErc1271Key() public {
        SHRINCS.Signature memory first = _sigFor(newPk);
        vm.prank(OWNER);
        wallet.setErc1271Key(_mainPk(), first, newPk, SUITE);
        assertEq(wallet.getErc1271PublicKeyCommitment(), newCommitment);

        SHRINCS.Signature memory sig = _signStatefulAction(
            Codec.ACTION_SET_ERC1271_KEY, Codec.setErc1271KeyPayloadHash(erc1271Commitment, SUITE), 2
        );
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(erc1271Pk.statefulPublicKey))
        );
        wallet.setErc1271Key(_mainPk(), sig, erc1271Pk, SUITE);
    }

    function test_setErc1271Key_succeeds() public {
        SHRINCS.Signature memory sig = _sigFor(newPk);
        bytes32 old = wallet.getErc1271PublicKeyCommitment();
        _assertTreesUnspent(newPk);
        vm.expectEmit(false, false, false, true, address(wallet));
        emit IShrincsWallet.Erc1271KeySet(old, newCommitment);
        vm.prank(OWNER);
        wallet.setErc1271Key(_mainPk(), sig, newPk, SUITE);
        assertEq(wallet.getErc1271PublicKeyCommitment(), newCommitment);
        _assertTreesSpent(newPk);
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 consumed");
        assertEq(wallet.actionNonce(), 1, "consumed signature advances the action nonce");
    }
}
