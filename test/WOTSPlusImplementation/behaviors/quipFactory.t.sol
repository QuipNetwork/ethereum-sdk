// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";

contract WOTSPlusImplementation_quipFactory is WOTSPlusImplementationTest {
    function test_quipFactory_returnsCorrectFactoryAddress() public view {
        assertEq(wallet.quipFactory(), payable(address(factory)));
    }
}
