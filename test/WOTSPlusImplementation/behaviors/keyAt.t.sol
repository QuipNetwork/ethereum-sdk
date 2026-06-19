// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/wots/EnumerableWinternitzAddressSet.sol";

contract WOTSPlusImplementation_keyAt is WOTSPlusImplementationTest {
    function test_keyAt_transactionReturnsMemberOfInitialKeys() public view {
        uint256 count = wallet.keyCount(Codec.KeyType.Transaction);
        for (uint256 i = 0; i < count; i++) {
            WOTSPlus.WinternitzAddress memory key = wallet.keyAt(Codec.KeyType.Transaction, i);
            bool matched;
            for (uint256 j = 0; j < aliceTxnPubkeys.length; j++) {
                if (
                    aliceTxnPubkeys[j].publicSeed == key.publicSeed
                        && aliceTxnPubkeys[j].publicKeyHash == key.publicKeyHash
                ) {
                    matched = true;
                    break;
                }
            }
            assertTrue(matched, "txn key at index not found in initial batch");
        }
    }

    function test_keyAt_transactionRevertsWhen_indexOutOfBounds() public {
        uint256 count = wallet.keyCount(Codec.KeyType.Transaction);
        vm.expectRevert(Keyset.IndexOutOfBounds.selector);
        wallet.keyAt(Codec.KeyType.Transaction, count);
    }

    function test_keyAt_recoveryReturnsMemberOfRegisteredKeys() public view {
        uint256 count = wallet.keyCount(Codec.KeyType.Recovery);
        for (uint256 i = 0; i < count; i++) {
            WOTSPlus.WinternitzAddress memory key = wallet.keyAt(Codec.KeyType.Recovery, i);
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

    function test_keyAt_recoveryRevertsWhen_indexOutOfBounds() public {
        uint256 count = wallet.keyCount(Codec.KeyType.Recovery);
        vm.expectRevert(Keyset.IndexOutOfBounds.selector);
        wallet.keyAt(Codec.KeyType.Recovery, count);
    }

    function test_keyAt_verificationReturnsCorrectPair() public {
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeys(3);

        for (uint256 i = 0; i < 3; i++) {
            WOTSPlus.WinternitzAddress memory key = wallet.keyAt(Codec.KeyType.Verification, i);
            // The set does not guarantee order, but the key at each index must
            // be a member of the seeded batch.
            bool matched;
            for (uint256 j = 0; j < 3; j++) {
                if (seeded[j].publicSeed == key.publicSeed && seeded[j].publicKeyHash == key.publicKeyHash) {
                    matched = true;
                    break;
                }
            }
            assertTrue(matched, "key at index not found in seeded batch");
        }
    }

    function test_keyAt_verificationRevertsWhen_outOfBounds() public {
        // resetKeyset installs MAX_KEYS=10; out-of-bounds is at index 10.
        _seedVerificationKeys(2);
        vm.expectRevert(Keyset.IndexOutOfBounds.selector);
        wallet.keyAt(Codec.KeyType.Verification, 10);
    }

    function test_keyAt_verificationReturnsAtInit() public view {
        WOTSPlus.WinternitzAddress memory key = wallet.keyAt(Codec.KeyType.Verification, 0);
        assertTrue(key.publicSeed != bytes32(0));
        assertTrue(key.publicKeyHash != bytes32(0));
    }
}
