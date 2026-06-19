// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for `setErc1271Key`. Reverts plus the success path (commitment +
///      param updated, `Erc1271KeySet`) are all exercised.
contract ShrincsWallet_setErc1271Key is ShrincsWalletTest {
    bytes32 internal constant NEW_COMMITMENT = keccak256("new-erc1271");

    function _pk() internal view returns (ShrincsTypes.PublicKey memory) {
        return _parsePublicKey(".mainKey");
    }

    function test_setErc1271Key_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.setErc1271Key(_pk(), _statefulSigWithLeaf(1), NEW_COMMITMENT, 0);
    }

    function test_setErc1271Key_revertsWhen_zeroCommitment() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ZeroErc1271Commitment.selector);
        wallet.setErc1271Key(_pk(), _statefulSigWithLeaf(1), bytes32(0), 0);
    }

    function test_setErc1271Key_revertsWhen_leafZero() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.setErc1271Key(_pk(), _statefulSigWithLeaf(0), NEW_COMMITMENT, 0);
    }

    function test_setErc1271Key_revertsWhen_leafOverBudget() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.setErc1271Key(_pk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1), NEW_COMMITMENT, 0);
    }

    function test_setErc1271Key_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(1);
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.setErc1271Key(_pk(), _statefulSigWithLeaf(1), NEW_COMMITMENT, 0);
    }

    function test_setErc1271Key_revertsWhen_invalidSignature() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.setErc1271Key(_pk(), _wrongContextStatefulSig(), NEW_COMMITMENT, 0);
    }

    function test_setErc1271Key_succeeds() public {
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.setErc1271Key.signature");
        bytes32 newCommitment = _bytes32(".cases.setErc1271Key.newCommitment");
        bytes32 old = wallet.getErc1271Commitment();
        vm.expectEmit(false, false, false, true, address(wallet));
        emit IShrincsWallet.Erc1271KeySet(old, newCommitment);
        vm.prank(OWNER);
        wallet.setErc1271Key(_pk(), sig, newCommitment, 0);
        assertEq(wallet.getErc1271Commitment(), newCommitment);
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 consumed");
    }
}
