// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet as Keyset} from
    "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

contract QuipWallet_getRecoveryKeyAt is QuipWalletTest {
    function test_getRecoveryKeyAt_returnsMemberOfRegisteredKeys() public view {
        uint256 count = wallet.getRecoveryKeyCount();
        for (uint256 i = 0; i < count; i++) {
            WOTSPlus.WinternitzAddress memory key = wallet.getRecoveryKeyAt(i);
            bool matched;
            for (uint256 j = 0; j < recoveryPubkeys.length; j++) {
                if (
                    recoveryPubkeys[j].publicSeed == key.publicSeed
                        && recoveryPubkeys[j].publicKeyHash == key.publicKeyHash
                ) {
                    matched = true;
                    break;
                }
            }
            assertTrue(matched, "key at index not found in registered batch");
        }
    }

    function test_getRecoveryKeyAt_revertsWhen_indexOutOfBounds() public {
        uint256 count = wallet.getRecoveryKeyCount();
        vm.expectRevert(Keyset.IndexOutOfBounds.selector);
        wallet.getRecoveryKeyAt(count);
    }
}
