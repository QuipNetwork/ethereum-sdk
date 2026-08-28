// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {SHRINCSVerifier} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCSVerifier.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for break-glass `recoverWallet` (stateless full-bundle rotation, same owner).
///      Access control, the `InvalidSignature` (statelessRotate returns zero) branch, and the
///      live-signed success path are all exercised.
contract ShrincsWallet_recoverWallet is ShrincsWalletTest {
    function _nextKey() internal view returns (SHRINCS.RotationTarget memory nextKey) {
        (nextKey,) = _makeRotationTarget("recover-wallet-next-key");
    }

    function test_recoverWallet_revertsWhen_notOwner() public {
        SPHINCSPlusC.Signature memory recoverySig;
        SHRINCS.RotationTarget memory nextKey;
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.recoverWallet(_mainPk(), recoverySig, nextKey);
    }

    function test_recoverWallet_revertsWhen_invalidRecoverySignature() public {
        SPHINCSPlusC.Signature memory recoverySig; // empty ⇒ statelessRotate returns zero
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.recoverWallet(_mainPk(), recoverySig, _nextKey());
    }

    function test_recoverWallet_succeeds() public {
        SHRINCS.RotationTarget memory nextKey = _nextKey();
        SPHINCSPlusC.Signature memory recoverySig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        bytes32 nextCommitment = _toBytes32(nextKey.publicKeyCommitment);
        uint256 nonceBefore = wallet.actionNonce();
        vm.prank(OWNER);
        wallet.recoverWallet(_mainPk(), recoverySig, nextKey);
        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommitment, "fresh recovery bundle installed");
        assertEq(wallet.owner(), OWNER, "owner unchanged on recovery");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
        assertEq(wallet.actionNonce(), nonceBefore + 1, "stateless path advances the action nonce");
    }

    /// @dev The stateless rotation verify must actually leave the wallet: a valid recovery
    ///      staticcalls the pinned verifier's `verifyStateless`.
    function test_recoverWallet_delegatesToVerifier() public {
        SHRINCS.RotationTarget memory nextKey = _nextKey();
        SPHINCSPlusC.Signature memory recoverySig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        vm.expectCall(
            address(shrincsVerifier), abi.encodeWithSelector(SHRINCSVerifier.verifyStateless.selector)
        );
        vm.prank(OWNER);
        wallet.recoverWallet(_mainPk(), recoverySig, nextKey);
        assertEq(
            wallet.getShrincsPublicKeyCommitment(),
            _toBytes32(nextKey.publicKeyCommitment),
            "rotation landed through the external verifier"
        );
    }

    /// @dev The handover→recovery downgrade: a recovery signature signed as part of a
    ///      `transferOwnership` bundle must NOT be accepted here — the tagged rotation domains
    ///      make the two stateless-rotation paths mutually invalid.
    function test_recoverWallet_revertsWhen_signatureSignedForTransferOwnership() public {
        SHRINCS.RotationTarget memory nextKey = _nextKey();
        SPHINCSPlusC.Signature memory handoverSig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.recoverWallet(_mainPk(), handoverSig, nextKey);
    }

    // The three guards below are wallet-side ONLY — the external verifier never sees the
    // rotation TARGET, so each must reject BEFORE any delegation happens (pinned by the
    // zero-count expectCall).

    function test_recoverWallet_revertsWhen_declaredNextCommitmentMismatch() public {
        SHRINCS.RotationTarget memory nextKey = _nextKey();
        SPHINCSPlusC.Signature memory recoverySig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        // Tamper the DECLARED commitment after signing: recompute-vs-declared must trip.
        nextKey.publicKeyCommitment = abi.encodePacked(keccak256("not-the-recomputed-commitment"));
        vm.expectCall(
            address(shrincsVerifier), abi.encodeWithSelector(SHRINCSVerifier.verifyStateless.selector), 0
        );
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.recoverWallet(_mainPk(), recoverySig, nextKey);
    }

    function test_recoverWallet_revertsWhen_zeroBudgetNextKey() public {
        SHRINCS.RotationTarget memory nextKey = _nextKey();
        SPHINCSPlusC.Signature memory recoverySig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        // Zero the 4-byte maxSignatures tail of the 68-byte stateful key: an unusable key
        // must be rejected by the wallet's budget guard, before any delegation.
        for (uint256 i = 64; i < 68; i++) {
            nextKey.statefulPublicKey[i] = 0;
        }
        vm.expectCall(
            address(shrincsVerifier), abi.encodeWithSelector(SHRINCSVerifier.verifyStateless.selector), 0
        );
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.recoverWallet(_mainPk(), recoverySig, nextKey);
    }

    function test_recoverWallet_revertsWhen_badNextKeyFieldWidths() public {
        SHRINCS.RotationTarget memory nextKey = _nextKey();
        SPHINCSPlusC.Signature memory recoverySig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        nextKey.pkSeed = new bytes(31); // fixed-width fields keep the rotation preimage canonical
        vm.expectCall(
            address(shrincsVerifier), abi.encodeWithSelector(SHRINCSVerifier.verifyStateless.selector), 0
        );
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.recoverWallet(_mainPk(), recoverySig, nextKey);
    }

    /*──────────────────── spent-tree tracking ────────────────────*/

    function test_recoverWallet_spendsBothNextTrees() public {
        (SHRINCS.RotationTarget memory t,) = _makeRotationTarget("recover-spends");
        SHRINCS.PublicKey memory next = _bundleOf(t);
        _assertTreesUnspent(next);
        SPHINCSPlusC.Signature memory sig = _signFullRotation(t, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        vm.prank(OWNER);
        wallet.recoverWallet(_mainPk(), sig, t);
        assertEq(wallet.getShrincsPublicKeyCommitment(), _toBytes32(next.publicKeyCommitment), "recovered");
        _assertTreesSpent(next);
    }

    function test_recoverWallet_revertsWhen_sameBundle() public {
        SHRINCS.RotationTarget memory same = _sameBundleTarget();
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

    function test_recoverWallet_revertsWhen_cyclingBackToEarlierBundle() public {
        SHRINCS.RotationTarget memory backToA = _sameBundleTarget();
        (SHRINCS.RotationTarget memory b, SHRINCS.SigningKey memory bKey) = _makeRotationTarget("recover-cycle-B");
        SPHINCSPlusC.Signature memory sigAB = _signFullRotation(b, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        vm.prank(OWNER);
        wallet.recoverWallet(_mainPk(), sigAB, b);
        assertEq(wallet.keyVersion(), 1);

        // Sign the B → A attempt with B (now installed). A's trees were spent at initialize.
        mainKey = bKey;
        mainPk = _bundleOf(b);
        SPHINCSPlusC.Signature memory sigBA = _signFullRotation(backToA, Codec.ROTATION_DOMAIN_RECOVER_WALLET);
        vm.prank(OWNER);
        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(backToA.statefulPublicKey))
        );
        wallet.recoverWallet(_mainPk(), sigBA, backToA);
    }
}
