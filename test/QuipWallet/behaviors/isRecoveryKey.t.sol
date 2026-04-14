// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet_isRecoveryKey is QuipWalletTest {
    function test_isRecoveryKey_returnsTrueForRegisteredKey() public view {
        assertTrue(wallet.isRecoveryKey(recoveryPubkeys[0]));
    }

    function test_isRecoveryKey_returnsTrueForAllRegisteredKeys() public view {
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertTrue(wallet.isRecoveryKey(recoveryPubkeys[i]));
        }
    }

    function test_isRecoveryKey_returnsFalseForUnregisteredKey() public {
        (WOTSPlus.WinternitzAddress memory other,) = _generateKeyPair("not-a-recovery-key");
        assertFalse(wallet.isRecoveryKey(other));
    }

    function test_isRecoveryKey_returnsFalseForZeroKey() public view {
        WOTSPlus.WinternitzAddress memory zero = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });
        assertFalse(wallet.isRecoveryKey(zero));
    }
}
