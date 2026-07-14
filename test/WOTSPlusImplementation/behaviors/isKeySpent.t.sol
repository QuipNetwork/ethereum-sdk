// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @dev Behaviour tests for the external `isKeySpent(key)` view. The
///      underlying `_isKeySpent` has comprehensive coverage in
///      `_isKeySpent.t.sol`; this file locks down the public surface that
///      off-chain callers (the TypeScript SDK simulator in particular) rely
///      on for pre-flight `NextKeyAlreadyInUse` checks.
contract WOTSPlusImplementation_isKeySpent is WOTSPlusImplementationTest {
    function test_isKeySpent_returnsTrueForInstalledTransactionKey() public view {
        for (uint256 i = 0; i < aliceTxnPubkeys.length; i++) {
            assertTrue(wallet.isKeySpent(aliceTxnPubkeys[i]));
        }
    }

    function test_isKeySpent_returnsTrueForInstalledRecoveryKey() public view {
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertTrue(wallet.isKeySpent(recoveryPubkeys[i]));
        }
    }

    function test_isKeySpent_returnsTrueForOwnershipKey() public view {
        assertTrue(wallet.isKeySpent(ownershipPubkey));
    }

    function test_isKeySpent_returnsTrueForDisasterRecoveryKey() public {
        (WOTSPlus.WinternitzAddress memory disasterKey,) = _generateDisasterRecoveryKey(VAULT_SEED);
        assertTrue(wallet.isKeySpent(disasterKey));
    }

    function test_isKeySpent_returnsFalseForUnknownKey() public {
        (WOTSPlus.WinternitzAddress memory unknown,) = _generateKeyPair("not-installed");
        assertFalse(wallet.isKeySpent(unknown));
    }

    function test_isKeySpent_returnsFalseForZeroKey() public view {
        WOTSPlus.WinternitzAddress memory zero =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        assertFalse(wallet.isKeySpent(zero));
    }
}
