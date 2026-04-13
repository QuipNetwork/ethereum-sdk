// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet_isVerificationKey is QuipWalletTest {
    function test_isVerificationKey_returnsTrueForMember() public {
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeyset(2);
        assertTrue(wallet.isVerificationKey(seeded[0]));
        assertTrue(wallet.isVerificationKey(seeded[1]));
    }

    function test_isVerificationKey_returnsFalseForNonMember() public {
        _seedVerificationKeyset(2);
        (WOTSPlus.WinternitzAddress memory other,) = _generateKeyPair("not-a-member");
        assertFalse(wallet.isVerificationKey(other));
    }

    function test_isVerificationKey_returnsFalseForAllNonMembersInEagerPhase() public {
        // Fill past the lazy→eager threshold so the position-mapping path is exercised.
        _seedVerificationKeyset(5);
        (WOTSPlus.WinternitzAddress memory other,) = _generateKeyPair("isvk-eager-nonmember");
        assertFalse(wallet.isVerificationKey(other));
    }
}
