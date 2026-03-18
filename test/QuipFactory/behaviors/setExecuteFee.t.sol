// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";

contract QuipFactory_setExecuteFee is QuipFactoryTest {
    function test_setExecuteFee_setsFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        assertEq(factory.executeFee(), EXECUTE_FEE);
    }

    function test_setExecuteFee_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ALICE));
        factory.setExecuteFee(EXECUTE_FEE);
    }

    function test_setExecuteFee_revertsWhen_feeExceedsMax() public {
        uint256 maxFee = factory.MAX_FEE();
        uint256 excessFee = maxFee + 1;
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(IQuipFactory.FeeExceedsMax.selector, excessFee, maxFee));
        factory.setExecuteFee(excessFee);
    }
}
