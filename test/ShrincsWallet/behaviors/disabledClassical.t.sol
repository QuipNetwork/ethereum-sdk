// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the disabled classical Ownable/ERC4337 entry points. The SHRINCS wallet
///      replaces each with a PQ-authenticated variant; the inherited classical ones must revert.
contract ShrincsWallet_disabledClassical is ShrincsWalletTest {
    // renounceOwnership keeps the `onlyOwner` gate, so the modifier trips before the body's revert.
    function test_renounceOwnership_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.renounceOwnership();
    }

    function test_renounceOwnership_revertsForOwner() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.RenounceDisabled.selector);
        wallet.renounceOwnership();
    }

    // transferOwnership(address) has no modifier — it reverts for every caller.
    function test_classicalTransferOwnership_revertsForOwner() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ClassicalTransferOwnershipDisabled.selector);
        wallet.transferOwnership(makeAddr("newOwner"));
    }

    function test_classicalTransferOwnership_revertsForStranger() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(IShrincsWallet.ClassicalTransferOwnershipDisabled.selector);
        wallet.transferOwnership(makeAddr("newOwner"));
    }

    function test_requestOwnershipHandover_reverts() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.OwnershipHandoverDisabled.selector);
        wallet.requestOwnershipHandover();
    }

    function test_cancelOwnershipHandover_reverts() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.OwnershipHandoverDisabled.selector);
        wallet.cancelOwnershipHandover();
    }

    function test_completeOwnershipHandover_reverts() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.OwnershipHandoverDisabled.selector);
        wallet.completeOwnershipHandover(makeAddr("pending"));
    }

    function test_classicalWithdrawDepositTo_revertsForOwner() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.ClassicalWithdrawDisabled.selector);
        wallet.withdrawDepositTo(makeAddr("to"), 1 ether);
    }

    function test_classicalWithdrawDepositTo_revertsForStranger() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(IShrincsWallet.ClassicalWithdrawDisabled.selector);
        wallet.withdrawDepositTo(makeAddr("to"), 1 ether);
    }
}
