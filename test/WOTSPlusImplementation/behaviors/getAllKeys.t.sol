// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusImplementation_getAllKeys is WOTSPlusImplementationTest {
    function test_getAllKeys_returnsFullState() public {
        // Seed two verification keys so all three keysets are non-empty.
        (WOTSPlus.WinternitzAddress[] memory verificationSeeded,) = _seedVerificationKeys(2);

        IWOTSPlusImplementation.AllKeys memory snap = wallet.getAllKeys();

        // Single-slot keys.
        WOTSPlus.WinternitzAddress memory dr = wallet.getDisasterRecoveryKey();
        WOTSPlus.WinternitzAddress memory ok = wallet.getOwnershipKey();
        assertEq(snap.disasterRecoveryKey.publicSeed, dr.publicSeed);
        assertEq(snap.disasterRecoveryKey.publicKeyHash, dr.publicKeyHash);
        assertEq(snap.ownershipKey.publicSeed, ok.publicSeed);
        assertEq(snap.ownershipKey.publicKeyHash, ok.publicKeyHash);

        // Keyset lengths match keyCount.
        assertEq(snap.transactionKeys.length, wallet.keyCount(Codec.KeyType.Transaction));
        assertEq(snap.recoveryKeys.length, wallet.keyCount(Codec.KeyType.Recovery));
        assertEq(snap.verificationKeys.length, wallet.keyCount(Codec.KeyType.Verification));

        // Each entry must be a member of the corresponding keyset.
        for (uint256 i = 0; i < snap.transactionKeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, snap.transactionKeys[i]));
        }
        for (uint256 i = 0; i < snap.recoveryKeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, snap.recoveryKeys[i]));
        }
        for (uint256 i = 0; i < snap.verificationKeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Verification, snap.verificationKeys[i]));
        }

        // `_seedVerificationKeys` always installs MAX_KEYS=10 via resetKeyset
        // (the `2` requested only sets the size of the returned helper array).
        assertEq(snap.verificationKeys.length, 10);
        assertEq(verificationSeeded.length, 2);
    }

    function test_getAllKeys_allKeysetsFullAtInit() public view {
        IWOTSPlusImplementation.AllKeys memory snap = wallet.getAllKeys();
        assertEq(snap.transactionKeys.length, 10);
        assertEq(snap.recoveryKeys.length, 10);
        assertEq(snap.verificationKeys.length, 10);
    }
}
