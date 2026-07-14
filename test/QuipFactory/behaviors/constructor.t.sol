// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipFactory} from "../../../contracts/QuipFactory.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";

/// @dev Behaviour tests for the QuipFactory constructor (per-implementation
///      immutable `MAX_FEE` + its single revert branch) and `initialize`
///      (proxy-side owner installation).
contract QuipFactory_constructor is QuipFactoryTest {
    function test_constructor_revertsWhen_maxFeeZero() public {
        vm.expectRevert(IQuipFactory.ZeroMaxFee.selector);
        new QuipFactory(0);
    }

    function test_constructor_setsMaxFeeImmutable() public {
        QuipFactory fresh = new QuipFactory(0.5 ether);
        assertEq(fresh.MAX_FEE(), 0.5 ether);
    }

    function test_initialize_setsInitialOwner() public {
        address freshOwner = makeAddr("fresh-owner");
        QuipFactory impl = new QuipFactory(1 ether);
        QuipFactory fresh = QuipFactory(payable(LibClone.deployERC1967(address(impl))));
        fresh.initialize(payable(freshOwner));
        assertEq(fresh.owner(), freshOwner);
        // MAX_FEE reads through the proxy from implementation code.
        assertEq(fresh.MAX_FEE(), 1 ether);
    }

    function test_initialize_revertsWhen_zeroOwner() public {
        QuipFactory impl = new QuipFactory(1 ether);
        QuipFactory fresh = QuipFactory(payable(LibClone.deployERC1967(address(impl))));
        vm.expectRevert(IQuipFactory.ZeroAddressOwner.selector);
        fresh.initialize(payable(address(0)));
    }
}
