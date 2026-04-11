// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";

contract QuipWallet_getRecoveryKeyCount is QuipWalletTest {
    function test_getRecoveryKeyCount_returnsTenAfterInit() public view {
        assertEq(wallet.getRecoveryKeyCount(), 10);
    }
}
