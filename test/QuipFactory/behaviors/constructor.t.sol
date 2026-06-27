// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipFactory} from "../../../contracts/QuipFactory.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";

/// @dev Behaviour tests for the QuipFactory constructor — the single explicit
///      revert branch (`maxFee_ == 0`) and the happy-path immutable assignment.
contract QuipFactory_constructor is QuipFactoryTest {
    function test_constructor_revertsWhen_maxFeeZero() public {
        vm.expectRevert(IQuipFactory.ZeroMaxFee.selector);
        new QuipFactory(payable(ADMIN), 0);
    }

    function test_constructor_setsMaxFeeImmutable() public {
        QuipFactory fresh = new QuipFactory(payable(ADMIN), 0.5 ether);
        assertEq(fresh.MAX_FEE(), 0.5 ether);
    }

    function test_constructor_setsInitialOwner() public {
        address freshOwner = makeAddr("fresh-owner");
        QuipFactory fresh = new QuipFactory(payable(freshOwner), 1 ether);
        assertEq(fresh.owner(), freshOwner);
    }
}
