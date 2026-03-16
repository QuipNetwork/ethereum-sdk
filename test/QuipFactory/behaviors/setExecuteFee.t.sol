// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {QuipFactoryTest} from "../QuipFactory.t.sol";

contract QuipFactory_setExecuteFee is QuipFactoryTest {
    function test_setExecuteFee_setsFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        assertEq(factory.executeFee(), EXECUTE_FEE);
    }

    function test_setExecuteFee_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert("You aren't the admin");
        factory.setExecuteFee(EXECUTE_FEE);
    }
}
