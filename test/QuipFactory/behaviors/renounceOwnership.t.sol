// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";

contract QuipFactory_renounceOwnership is QuipFactoryTest {
    function test_renounceOwnership_revertsWhen_calledByOwner() public {
        vm.prank(ADMIN);
        vm.expectRevert(IQuipFactory.RenounceDisabled.selector);
        factory.renounceOwnership();
    }

    function test_renounceOwnership_revertsWhen_calledByNonOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                ALICE
            )
        );
        factory.renounceOwnership();
    }
}
