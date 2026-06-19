// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for break-glass `recoverWallet` (stateless full-bundle rotation, same owner).
///      Access control, stateless-budget exhaustion, and the `InvalidSignature` (statelessRotate
///      returns zero) branch and the regenerated-vector success path are all exercised.
contract ShrincsWallet_recoverWallet is ShrincsWalletTest {
    function _pk() internal view returns (ShrincsTypes.PublicKey memory) {
        return _parsePublicKey(".mainKey");
    }

    function _nextKey() internal view returns (ShrincsTypes.RotationTarget memory) {
        return _parseRotationTarget(".cases.rotateFullKey.nextKey");
    }

    function test_recoverWallet_revertsWhen_notOwner() public {
        ShrincsTypes.StatelessSignature memory recoverySig;
        ShrincsTypes.RotationTarget memory nextKey;
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.recoverWallet(_pk(), recoverySig, nextKey);
    }

    function test_recoverWallet_revertsWhen_statelessBudgetExhausted() public {
        wallet.harness_setStatelessUsed(uint64(wallet.statelessSignatureLimit()));
        ShrincsTypes.StatelessSignature memory recoverySig;
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatelessBudgetExhausted.selector);
        wallet.recoverWallet(_pk(), recoverySig, _nextKey());
    }

    function test_recoverWallet_revertsWhen_invalidRecoverySignature() public {
        ShrincsTypes.StatelessSignature memory recoverySig; // empty ⇒ statelessRotate returns zero
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.recoverWallet(_pk(), recoverySig, _nextKey());
    }

    function test_recoverWallet_succeeds() public {
        ShrincsTypes.StatelessSignature memory recoverySig = _parseStatelessSignature(".cases.rotateFullKey.signature");
        bytes32 nextCommitment = _bytes32(".cases.rotateFullKey.nextKey.publicKeyCommitment");
        uint256 nonceBefore = wallet.actionNonce();
        vm.prank(OWNER);
        wallet.recoverWallet(_pk(), recoverySig, _nextKey());
        assertEq(wallet.getShrincsPublicKeyCommitment(), nextCommitment, "fresh recovery bundle installed");
        assertEq(wallet.owner(), OWNER, "owner unchanged on recovery");
        assertEq(wallet.keyVersion(), 1, "epoch bumped");
        assertEq(wallet.actionNonce(), nonceBefore + 1, "stateless path advances the action nonce");
        assertEq(wallet.statelessSignaturesUsed(), 0, "counters reset");
    }
}
