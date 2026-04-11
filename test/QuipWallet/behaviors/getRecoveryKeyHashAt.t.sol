// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract QuipWallet_getRecoveryKeyHashAt is QuipWalletTest {
    function test_getRecoveryKeyHashAt_returnsCorrectHashForIndexZero() public view {
        bytes32 expectedHash = EfficientHashLib.hash(
            recoveryPubkeys[0].publicSeed,
            recoveryPubkeys[0].publicKeyHash
        );
        assertEq(wallet.getRecoveryKeyHashAt(0), expectedHash);
    }

    function test_getRecoveryKeyHashAt_returnsCorrectHashForLastIndex() public view {
        uint256 lastIndex = wallet.getRecoveryKeyCount() - 1;
        bytes32 expectedHash = EfficientHashLib.hash(
            recoveryPubkeys[lastIndex].publicSeed,
            recoveryPubkeys[lastIndex].publicKeyHash
        );
        assertEq(wallet.getRecoveryKeyHashAt(lastIndex), expectedHash);
    }

    function test_getRecoveryKeyHashAt_revertsWhen_indexOutOfBounds() public {
        uint256 count = wallet.getRecoveryKeyCount();
        vm.expectRevert();
        wallet.getRecoveryKeyHashAt(count);
    }
}
