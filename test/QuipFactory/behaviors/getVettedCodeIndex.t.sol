// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";

contract QuipFactory_getVettedCodeIndex is QuipFactoryTest {
    function test_getVettedCodeIndex_returnsIndexForVettedImpl() public view {
        bytes32 codehash = address(walletImplementation).codehash;
        assertEq(factory.getVettedCodeIndex(codehash), 0);
    }

    function test_getVettedCodeIndex_returnsCorrectIndexForMultipleImpls()
        public
    {
        QuipWallet secondImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(secondImpl));

        assertEq(
            factory.getVettedCodeIndex(address(walletImplementation).codehash),
            0
        );
        assertEq(factory.getVettedCodeIndex(address(secondImpl).codehash), 1);
    }

    function test_getVettedCodeIndex_returnsNotFoundForUnknownCodehash()
        public
        view
    {
        assertEq(
            factory.getVettedCodeIndex(bytes32(uint256(0xdead))),
            type(uint256).max
        );
    }
}
