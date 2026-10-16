// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";

contract WalletFactory_getVettedCodeCount is WalletFactoryTest {
    function test_getVettedCodeCount_returnsOneAfterSetUp() public view {
        assertEq(factory.getVettedCodeCount(), 1);
    }

    function test_getVettedCodeCount_incrementsAfterVetting() public {
        WOTSPlusImplementation secondImpl = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(secondImpl));

        assertEq(factory.getVettedCodeCount(), 2);
    }
}
