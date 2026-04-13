// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet as Keyset} from
    "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

contract QuipWallet_getVerificationKeyAt is QuipWalletTest {
    function test_getVerificationKeyAt_returnsCorrectPair() public {
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeyset(3);

        for (uint256 i = 0; i < 3; i++) {
            WOTSPlus.WinternitzAddress memory key = wallet.getVerificationKeyAt(i);
            // The set does not guarantee order, but the key at each index must
            // be a member of the seeded batch.
            bool matched;
            for (uint256 j = 0; j < 3; j++) {
                if (
                    seeded[j].publicSeed == key.publicSeed
                        && seeded[j].publicKeyHash == key.publicKeyHash
                ) {
                    matched = true;
                    break;
                }
            }
            assertTrue(matched, "key at index not found in seeded batch");
        }
    }

    function test_getVerificationKeyAt_revertsWhen_outOfBounds() public {
        _seedVerificationKeyset(2);
        vm.expectRevert(Keyset.IndexOutOfBounds.selector);
        wallet.getVerificationKeyAt(2);
    }

    function test_getVerificationKeyAt_revertsWhen_emptySet() public {
        vm.expectRevert(Keyset.IndexOutOfBounds.selector);
        wallet.getVerificationKeyAt(0);
    }
}
