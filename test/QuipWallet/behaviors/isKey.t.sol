// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet_isKey is QuipWalletTest {
    function test_isKey_transactionReturnsTrueForRegisteredKey() public view {
        for (uint256 i = 0; i < aliceTxnPubkeys.length; i++) {
            assertTrue(
                wallet.isKey(
                    Codec.KeyType.Transaction,
                    aliceTxnPubkeys[i]
                )
            );
        }
    }

    function test_isKey_transactionReturnsFalseForUnregisteredKey() public {
        (WOTSPlus.WinternitzAddress memory other, ) = _generateKeyPair(
            "not-a-txn-key"
        );
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, other));
    }

    function test_isKey_recoveryReturnsTrueForRegisteredKey() public view {
        assertTrue(
            wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[0])
        );
    }

    function test_isKey_recoveryReturnsTrueForAllRegisteredKeys() public view {
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertTrue(
                wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i])
            );
        }
    }

    function test_isKey_recoveryReturnsFalseForUnregisteredKey() public {
        (WOTSPlus.WinternitzAddress memory other, ) = _generateKeyPair(
            "not-a-recovery-key"
        );
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, other));
    }

    function test_isKey_recoveryReturnsFalseForZeroKey() public view {
        WOTSPlus.WinternitzAddress memory zero = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, zero));
    }

    function test_isKey_verificationReturnsTrueForMember() public {
        (WOTSPlus.WinternitzAddress[] memory seeded, ) = _seedVerificationKeys(
            2
        );
        assertTrue(wallet.isKey(Codec.KeyType.Verification, seeded[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Verification, seeded[1]));
    }

    function test_isKey_verificationReturnsFalseForNonMember() public {
        _seedVerificationKeys(2);
        (WOTSPlus.WinternitzAddress memory other, ) = _generateKeyPair(
            "not-a-member"
        );
        assertFalse(wallet.isKey(Codec.KeyType.Verification, other));
    }

    function test_isKey_verificationReturnsFalseForAllNonMembersInEagerPhase()
        public
    {
        // Fill past the lazy→eager threshold so the position-mapping path is exercised.
        _seedVerificationKeys(5);
        (WOTSPlus.WinternitzAddress memory other, ) = _generateKeyPair(
            "isvk-eager-nonmember"
        );
        assertFalse(wallet.isKey(Codec.KeyType.Verification, other));
    }
}
