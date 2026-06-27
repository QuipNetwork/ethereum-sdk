// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";

contract QuipFactory_getVettedCodeCount is QuipFactoryTest {
    function test_getVettedCodeCount_returnsOneAfterSetUp() public view {
        assertEq(factory.getVettedCodeCount(), 1);
    }

    function test_getVettedCodeCount_incrementsAfterVetting() public {
        QuipWallet secondImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(secondImpl));

        assertEq(factory.getVettedCodeCount(), 2);
    }
}
