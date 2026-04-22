// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";

contract QuipFactory_getVettedCodeAt is QuipFactoryTest {
    function test_getVettedCodeAt_returnsCorrectCodehashAtIndexZero()
        public
        view
    {
        bytes32 expectedCodehash = address(walletImplementation).codehash;
        assertEq(factory.getVettedCodeAt(0), expectedCodehash);
    }

    function test_getVettedCodeAt_returnsCorrectCodehashForSecondImpl() public {
        QuipWallet secondImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(secondImpl));

        assertEq(factory.getVettedCodeAt(1), address(secondImpl).codehash);
    }

    function test_getVettedCodeAt_revertsWhen_indexOutOfBounds() public {
        uint256 count = factory.getVettedCodeCount();
        vm.expectRevert();
        factory.getVettedCodeAt(count);
    }
}
