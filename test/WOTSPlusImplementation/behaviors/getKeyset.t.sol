// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusImplementation_getKeyset is WOTSPlusImplementationTest {
    function test_getKeyset_transactionReturnsAllInitialKeys() public view {
        WOTSPlus.WinternitzAddress[] memory keys = wallet.getKeyset(Codec.KeyType.Transaction);
        assertEq(keys.length, 10);
        // Every entry must be one of the initial txn keys; collectively
        // the set must cover the whole batch.
        bool[10] memory seen;
        for (uint256 i = 0; i < keys.length; i++) {
            bool matched;
            for (uint256 j = 0; j < aliceTxnPubkeys.length; j++) {
                if (
                    aliceTxnPubkeys[j].publicSeed == keys[i].publicSeed
                        && aliceTxnPubkeys[j].publicKeyHash == keys[i].publicKeyHash
                ) {
                    assertFalse(seen[j], "duplicate key in keyset");
                    seen[j] = true;
                    matched = true;
                    break;
                }
            }
            assertTrue(matched, "txn key not found in initial batch");
        }
    }

    function test_getKeyset_transactionMatchesKeyCountAndKeyAt() public view {
        uint256 count = wallet.keyCount(Codec.KeyType.Transaction);
        WOTSPlus.WinternitzAddress[] memory keys = wallet.getKeyset(Codec.KeyType.Transaction);
        assertEq(keys.length, count);
        for (uint256 i = 0; i < count; i++) {
            WOTSPlus.WinternitzAddress memory byIndex = wallet.keyAt(Codec.KeyType.Transaction, i);
            assertEq(keys[i].publicSeed, byIndex.publicSeed);
            assertEq(keys[i].publicKeyHash, byIndex.publicKeyHash);
        }
    }

    function test_getKeyset_recoveryReturnsAllRegisteredKeys() public view {
        WOTSPlus.WinternitzAddress[] memory keys = wallet.getKeyset(Codec.KeyType.Recovery);
        assertEq(keys.length, 10);
        bool[10] memory seen;
        for (uint256 i = 0; i < keys.length; i++) {
            bool matched;
            for (uint256 j = 0; j < recoveryPubkeys.length; j++) {
                if (
                    recoveryPubkeys[j].publicSeed == keys[i].publicSeed
                        && recoveryPubkeys[j].publicKeyHash == keys[i].publicKeyHash
                ) {
                    assertFalse(seen[j], "duplicate key in keyset");
                    seen[j] = true;
                    matched = true;
                    break;
                }
            }
            assertTrue(matched, "recovery key not found in registered batch");
        }
    }

    function test_getKeyset_verificationReturnsTenAtInit() public view {
        WOTSPlus.WinternitzAddress[] memory keys = wallet.getKeyset(Codec.KeyType.Verification);
        assertEq(keys.length, 10);
    }

    function test_getKeyset_verificationReturnsSeededBatch() public {
        // `_seedVerificationKeys` always installs MAX_KEYS=10 (returns the
        // first `n` of them). The full keyset must contain each returned key.
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeys(3);
        WOTSPlus.WinternitzAddress[] memory keys = wallet.getKeyset(Codec.KeyType.Verification);
        assertEq(keys.length, 10);
        for (uint256 j = 0; j < seeded.length; j++) {
            bool found;
            for (uint256 i = 0; i < keys.length; i++) {
                if (seeded[j].publicSeed == keys[i].publicSeed && seeded[j].publicKeyHash == keys[i].publicKeyHash) {
                    found = true;
                    break;
                }
            }
            assertTrue(found, "seeded key not present in keyset");
        }
    }
}
