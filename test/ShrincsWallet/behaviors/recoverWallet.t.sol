// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.2.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for break-glass `recoverWallet` (stateless full-bundle rotation, same owner).
///      Access control, the `InvalidSignature` (statelessRotate returns zero) branch, and the
///      live-signed success path are all exercised.
contract ShrincsWallet_recoverWallet is ShrincsWalletTest {
    function _nextKey() internal pure returns (ShrincsTypes.RotationTarget memory nextKey) {
        (nextKey,) = _makeRotationTarget("recover-wallet-next-key");
    }

    function test_recoverWallet_revertsWhen_notOwner() public {
        ShrincsTypes.StatelessSignature memory recoverySig;
        ShrincsTypes.RotationTarget memory nextKey;
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.recoverWallet(_mainPk(), recoverySig, nextKey);
    }

    function test_recoverWallet_revertsWhen_invalidRecoverySignature() public {
        ShrincsTypes.StatelessSignature memory recoverySig; // empty ⇒ statelessRotate returns zero
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.recoverWallet(_mainPk(), recoverySig, _nextKey());
    }

    function test_recoverWallet_succeeds() public {
        ShrincsTypes.RotationTarget memory nextKey = _nextKey();
        ShrincsTypes.StatelessSignature memory recoverySig =
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

    /// @dev The handover→recovery downgrade: a recovery signature signed as part of a
    ///      `transferOwnership` bundle must NOT be accepted here — the tagged rotation domains
    ///      make the two stateless-rotation paths mutually invalid.
    function test_recoverWallet_revertsWhen_signatureSignedForTransferOwnership() public {
        ShrincsTypes.RotationTarget memory nextKey = _nextKey();
        ShrincsTypes.StatelessSignature memory handoverSig =
            _signFullRotation(nextKey, Codec.ROTATION_DOMAIN_TRANSFER_OWNERSHIP);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.recoverWallet(_mainPk(), handoverSig, nextKey);
    }
}
