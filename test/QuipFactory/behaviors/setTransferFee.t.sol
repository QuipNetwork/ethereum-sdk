// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {QuipFactoryTest} from "../QuipFactory.t.sol";

contract QuipFactory_setTransferFee is QuipFactoryTest {
    function test_setTransferFee_setsFee() public {
        vm.prank(ADMIN);
        factory.setTransferFee(TRANSFER_FEE);

        assertEq(factory.transferFee(), TRANSFER_FEE);
    }

    function test_setTransferFee_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert("You aren't the admin");
        factory.setTransferFee(TRANSFER_FEE);
    }
}
