// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";

contract QuipWallet_quipFactory is QuipWalletTest {
    function test_quipFactory_returnsCorrectFactoryAddress() public view {
        assertEq(wallet.quipFactory(), payable(address(factory)));
    }
}
