// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";

contract QuipFactory_setTransferFee is QuipFactoryTest {
    function test_setTransferFee_setsFee() public {
        vm.prank(ADMIN);
        factory.setTransferFee(TRANSFER_FEE);

        assertEq(factory.transferFee(), TRANSFER_FEE);
    }

    function test_setTransferFee_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ALICE));
        factory.setTransferFee(TRANSFER_FEE);
    }
}
