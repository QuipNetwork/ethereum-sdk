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

/// @dev Behavior tests for the atomic ownership-handover `transferOwnership`. Access control, input
///      validation, and the stateless-rotate `InvalidSignature` branch are covered, plus the full
///      dual-signature happy path (a stateless recovery rotation AND a stateful owner-binding
///      signature over `(newOwner, nextCommitment)`) and its cross-binding check — all signed live.
contract ShrincsWallet_transferOwnership is ShrincsWalletTest {
    address internal NEW_OWNER = makeAddr("newOwner");

    /// @dev A structurally-valid next-key bundle to drive past argument decoding (the rotation
    ///      still fails verification with an empty recovery signature).
    function _nextKey() internal view returns (SHRINCS.RotationTarget memory nextKey) {
        (nextKey,) = _makeRotationTarget("transfer-ownership-next-key");
    }

    /// @dev Stateful owner-binding signature cross-binding `newOwner` to the incoming bundle.
    function _ownerBindingSig(address newOwner, bytes32 nextCommitment)
        internal
        view
        returns (SHRINCS.Signature memory)
    {
        return _signStatefulAction(
            Codec.ACTION_TRANSFER_OWNERSHIP, Codec.transferOwnershipPayloadHash(newOwner, nextCommitment), 1
        );
    }

    function test_transferOwnership_revertsWhen_notOwner() public {
        SHRINCS.Signature memory ownerSig;
        SPHINCSPlusC.Signature memory recoverySig;
        SHRINCS.RotationTarget memory nextKey;
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER);
    }

    function test_transferOwnership_revertsWhen_zeroOwner() public {
        SHRINCS.Signature memory ownerSig;
        SPHINCSPlusC.Signature memory recoverySig;
        SHRINCS.RotationTarget memory nextKey;
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ZeroAddressOwner.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, address(0));
    }

    function test_transferOwnership_revertsWhen_invalidRecoverySignature() public {
        // An empty recovery signature makes `statelessRotate` return the zero commitment,
        // surfaced as InvalidSignature.
        SHRINCS.Signature memory ownerSig;
        SPHINCSPlusC.Signature memory recoverySig;
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, _nextKey(), NEW_OWNER);
    }

    function test_transferOwnership_fullHandover() public {
        SHRINCS.RotationTarget memory nextKey = _nextKey();
        bytes32 nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
        SPHINCSPlusC.Signature memory recoverySig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        SHRINCS.Signature memory ownerSig = _ownerBindingSig(NEW_OWNER, nextCommitment);

        uint256 nonceBefore = wallet.actionNonce();
        vm.prank(OWNER);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER);
        assertEq(wallet.owner(), NEW_OWNER, "classical owner handed over");
        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommitment, "fresh bundle installed for the new owner");
        assertEq(factory.lastOwnerUpdate(address(wallet)), NEW_OWNER, "factory registry synced");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
        // Two signatures consumed (stateful owner-binding + stateless rotation), both bound to
        // the pre-call nonce — nets exactly +2.
        assertEq(wallet.actionNonce(), nonceBefore + 2, "handover consumes two signatures");
    }

    function test_transferOwnership_crossBindingMismatch() public {
        // The stateless rotation succeeds, but a `newOwner` not matching the stateful owner-binding
        // signature's `(newOwner, nextCommitment)` payload fails verification.
        SHRINCS.RotationTarget memory nextKey = _nextKey();
        bytes32 nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
        SPHINCSPlusC.Signature memory recoverySig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        SHRINCS.Signature memory ownerSig = _ownerBindingSig(NEW_OWNER, nextCommitment);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, makeAddr("wrongOwner"));
    }

    /// @dev The recovery→handover direction: a recovery signature signed for `recoverWallet`
    ///      must NOT serve as the recovery half of a handover bundle — rejected by the tagged
    ///      rotation domain (independently of the owner-binding signature, which is also valid
    ///      here to isolate what is being tested).
    function test_transferOwnership_revertsWhen_signatureSignedForRecoverWallet() public {
        SHRINCS.RotationTarget memory nextKey = _nextKey();
        bytes32 nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
        SPHINCSPlusC.Signature memory recoverySig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        SHRINCS.Signature memory ownerSig = _ownerBindingSig(NEW_OWNER, nextCommitment);

        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, nextKey, NEW_OWNER);
    }

    /*──────────────────── spent-tree tracking ────────────────────*/

    function test_transferOwnership_spendsBothNextTrees() public {
        (SHRINCS.RotationTarget memory t,) = _makeRotationTarget("transfer-spends");
        SHRINCS.PublicKey memory next = _bundleOf(t);
        _assertTreesUnspent(next);
        bytes32 c = _toBytes32(next.publicKeyCommitment);
        SPHINCSPlusC.Signature memory recoverySig = _signFullRotation(t, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        SHRINCS.Signature memory ownerSig = _ownerBindingSig(NEW_OWNER, c);
        vm.prank(OWNER);
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, t, NEW_OWNER);
        assertEq(wallet.owner(), NEW_OWNER, "handed over");
        _assertTreesSpent(next);
    }

    function test_transferOwnership_revertsWhen_sameBundle() public {
        SHRINCS.RotationTarget memory same = _sameBundleTarget();
        SPHINCSPlusC.Signature memory recoverySig = _signFullRotation(same, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        SHRINCS.Signature memory ownerSig = _ownerBindingSig(NEW_OWNER, mainCommitment);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(mainPk.statefulPublicKey))
        );
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, same, NEW_OWNER);
    }

    function test_transferOwnership_revertsWhen_statelessTreeCarriedForward() public {
        SHRINCS.RotationTarget memory t = _freshStatefulSameStatelessTarget("transfer-carry-stateless");
        SPHINCSPlusC.Signature memory recoverySig = _signFullRotation(t, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        SHRINCS.Signature memory ownerSig = _ownerBindingSig(NEW_OWNER, _toBytes32(t.publicKeyCommitment));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.transferOwnership(_mainPk(), ownerSig, recoverySig, t, NEW_OWNER);
    }
}
