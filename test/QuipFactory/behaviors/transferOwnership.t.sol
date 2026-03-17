// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";

contract QuipFactory_transferOwnership is QuipFactoryTest {
    function test_transferOwnership_setsNewOwner() public {
        assertEq(factory.admin(), ADMIN);

        vm.prank(ADMIN);
        factory.transferOwnership(ALICE);

        assertEq(factory.admin(), ALICE);
    }

    function test_transferOwnership_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert("You aren't the admin");
        factory.transferOwnership(ALICE);
    }
}
