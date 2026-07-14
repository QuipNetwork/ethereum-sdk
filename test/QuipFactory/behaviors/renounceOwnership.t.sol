// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipFactory_renounceOwnership is QuipFactoryTest {
    function test_renounceOwnership_revertsWhen_calledByOwner() public {
        vm.prank(ADMIN);
        vm.expectRevert(IQuipFactory.RenounceDisabled.selector);
        factory.renounceOwnership();
    }

    function test_renounceOwnership_revertsWhen_calledByNonOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.renounceOwnership();
    }
}
