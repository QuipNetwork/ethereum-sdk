// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract QuipWallet_isRecoveryKey is QuipWalletTest {
    function test_isRecoveryKey_returnsTrueForRegisteredKeyHash() public view {
        bytes32 keyHash = EfficientHashLib.hash(
            recoveryPubkeys[0].publicSeed,
            recoveryPubkeys[0].publicKeyHash
        );
        assertTrue(wallet.isRecoveryKey(keyHash));
    }

    function test_isRecoveryKey_returnsTrueForAllRegisteredKeys() public view {
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            bytes32 keyHash = EfficientHashLib.hash(
                recoveryPubkeys[i].publicSeed,
                recoveryPubkeys[i].publicKeyHash
            );
            assertTrue(wallet.isRecoveryKey(keyHash));
        }
    }

    function test_isRecoveryKey_returnsFalseForUnregisteredKeyHash() public view {
        bytes32 fakeHash = keccak256("not-a-recovery-key");
        assertFalse(wallet.isRecoveryKey(fakeHash));
    }

    function test_isRecoveryKey_returnsFalseForZeroHash() public view {
        assertFalse(wallet.isRecoveryKey(bytes32(0)));
    }
}
