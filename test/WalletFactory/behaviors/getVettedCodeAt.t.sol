// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";

contract WalletFactory_getVettedCodeAt is WalletFactoryTest {
    function test_getVettedCodeAt_returnsCorrectCodehashAtIndexZero() public view {
        bytes32 expectedCodehash = address(walletImplementation).codehash;
        assertEq(factory.getVettedCodeAt(0), expectedCodehash);
    }

    function test_getVettedCodeAt_returnsCorrectCodehashForSecondImpl() public {
        WOTSPlusImplementation secondImpl = new WOTSPlusImplementation(payable(address(factory)));
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
