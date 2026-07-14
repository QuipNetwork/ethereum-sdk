// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {IWOTSPlusImplementation} from "../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

/// @dev Behaviour tests for the disabled Solady two-step ownership handover
///      surface. The wallet's only ownership-transfer path is the
///      WOTS+-authenticated `transferOwnership(bytes)`; every inherited
///      handover entry point reverts with `OwnershipHandoverDisabled` so an
///      EOA cannot stage a partial-handover state that would confuse off-chain
///      tooling, the registry callback, or Solady's pending-owner machinery.
contract WOTSPlusImplementation_ownershipHandoverDisabled is WOTSPlusImplementationTest {
    function test_requestOwnershipHandover_reverts() public {
        vm.expectRevert(IWOTSPlusImplementation.OwnershipHandoverDisabled.selector);
        vm.prank(BOB);
        wallet.requestOwnershipHandover();
    }

    function test_cancelOwnershipHandover_reverts() public {
        vm.expectRevert(IWOTSPlusImplementation.OwnershipHandoverDisabled.selector);
        vm.prank(BOB);
        wallet.cancelOwnershipHandover();
    }

    function test_classicalCompleteOwnershipHandover_reverts() public {
        vm.expectRevert(IWOTSPlusImplementation.OwnershipHandoverDisabled.selector);
        vm.prank(ALICE);
        wallet.completeOwnershipHandover(BOB);
    }

    function test_classicalCompleteOwnershipHandover_revertsForNonOwner() public {
        // Reverts the same way for non-owner callers — the disable predicate
        // sits BEFORE Solady's onlyOwner gate.
        vm.expectRevert(IWOTSPlusImplementation.OwnershipHandoverDisabled.selector);
        vm.prank(BOB);
        wallet.completeOwnershipHandover(BOB);
    }

    function test_ownershipHandoverExpiresAt_returnsZero() public view {
        assertEq(wallet.ownershipHandoverExpiresAt(BOB), 0);
        assertEq(wallet.ownershipHandoverExpiresAt(ALICE), 0);
        assertEq(wallet.ownershipHandoverExpiresAt(address(0)), 0);
    }
}
