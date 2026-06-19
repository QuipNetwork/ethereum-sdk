// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";

contract QuipFactory_transferOwnership is QuipFactoryTest {
    function test_transferOwnership_setsPendingOwner() public {
        assertEq(factory.owner(), ADMIN);

        vm.prank(ADMIN);
        factory.transferOwnership(ALICE);

        assertEq(factory.pendingOwner(), ALICE);
        // Owner hasn't changed yet
        assertEq(factory.owner(), ADMIN);
    }

    function test_transferOwnership_acceptOwnership_completesTransfer() public {
        vm.prank(ADMIN);
        factory.transferOwnership(ALICE);

        vm.prank(ALICE);
        factory.acceptOwnership();

        assertEq(factory.owner(), ALICE);
        assertEq(factory.pendingOwner(), address(0));
    }

    function test_transferOwnership_revertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ALICE));
        factory.transferOwnership(ALICE);
    }

    function test_acceptOwnership_revertsWhen_callerNotPendingOwner() public {
        vm.prank(ADMIN);
        factory.transferOwnership(ALICE);

        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, BOB));
        factory.acceptOwnership();
    }
}
