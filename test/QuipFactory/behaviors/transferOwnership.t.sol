// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

/// @dev Solady Ownable semantics: `transferOwnership(newOwner)` is IMMEDIATE
///      (unlike the previous OZ Ownable2Step pending/accept flow). The
///      two-step alternative is Solady's ownership handover, initiated by the
///      INCOMING owner (`requestOwnershipHandover`) and completed by the
///      current owner (`completeOwnershipHandover`). Both paths stay enabled
///      on the factory — a deliberate scope decision (FACTORY_UPGRADEABILITY.md),
///      unlike the wallets, which disable the entire classical surface.
contract QuipFactory_transferOwnership is QuipFactoryTest {
    function test_transferOwnership_transfersImmediately() public {
        assertEq(factory.owner(), ADMIN);

        vm.prank(ADMIN);
        factory.transferOwnership(ALICE);

        assertEq(factory.owner(), ALICE);
    }

    function test_transferOwnership_revertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.transferOwnership(ALICE);
    }

    function test_transferOwnership_revertsWhen_zeroAddress() public {
        vm.prank(ADMIN);
        vm.expectRevert(Ownable.NewOwnerIsZeroAddress.selector);
        factory.transferOwnership(address(0));
    }

    function test_ownershipHandover_completesTransfer() public {
        vm.prank(ALICE);
        factory.requestOwnershipHandover();

        vm.prank(ADMIN);
        factory.completeOwnershipHandover(ALICE);

        assertEq(factory.owner(), ALICE);
    }

    function test_ownershipHandover_completeRevertsWhen_noRequest() public {
        vm.prank(ADMIN);
        vm.expectRevert(Ownable.NoHandoverRequest.selector);
        factory.completeOwnershipHandover(ALICE);
    }

    function test_ownershipHandover_completeRevertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        factory.requestOwnershipHandover();

        vm.prank(BOB);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.completeOwnershipHandover(ALICE);
    }

    function test_ownershipHandover_cancelBlocksCompletion() public {
        vm.prank(ALICE);
        factory.requestOwnershipHandover();
        vm.prank(ALICE);
        factory.cancelOwnershipHandover();

        vm.prank(ADMIN);
        vm.expectRevert(Ownable.NoHandoverRequest.selector);
        factory.completeOwnershipHandover(ALICE);
    }
}
