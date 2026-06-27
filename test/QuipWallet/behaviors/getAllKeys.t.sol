// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {QuipWalletTest} from "../QuipWallet.t.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet_getAllKeys is QuipWalletTest {
    function test_getAllKeys_returnsFullState() public {
        // Seed two verification keys so all three keysets are non-empty.
        (
            WOTSPlus.WinternitzAddress[] memory verificationSeeded,
        ) = _seedVerificationKeys(2);

        IQuipWallet.AllKeys memory snap = wallet.getAllKeys();

        // Single-slot keys.
        WOTSPlus.WinternitzAddress memory dr = wallet.getDisasterRecoveryKey();
        WOTSPlus.WinternitzAddress memory ok = wallet.getOwnershipKey();
        assertEq(snap.disasterRecoveryKey.publicSeed, dr.publicSeed);
        assertEq(snap.disasterRecoveryKey.publicKeyHash, dr.publicKeyHash);
        assertEq(snap.ownershipKey.publicSeed, ok.publicSeed);
        assertEq(snap.ownershipKey.publicKeyHash, ok.publicKeyHash);

        // Keyset lengths match keyCount.
        assertEq(
            snap.transactionKeys.length,
            wallet.keyCount(Codec.KeyType.Transaction)
        );
        assertEq(
            snap.recoveryKeys.length,
            wallet.keyCount(Codec.KeyType.Recovery)
        );
        assertEq(
            snap.verificationKeys.length,
            wallet.keyCount(Codec.KeyType.Verification)
        );

        // Each entry must be a member of the corresponding keyset.
        for (uint256 i = 0; i < snap.transactionKeys.length; i++) {
            assertTrue(
                wallet.isKey(Codec.KeyType.Transaction, snap.transactionKeys[i])
            );
        }
        for (uint256 i = 0; i < snap.recoveryKeys.length; i++) {
            assertTrue(
                wallet.isKey(Codec.KeyType.Recovery, snap.recoveryKeys[i])
            );
        }
        for (uint256 i = 0; i < snap.verificationKeys.length; i++) {
            assertTrue(
                wallet.isKey(
                    Codec.KeyType.Verification,
                    snap.verificationKeys[i]
                )
            );
        }

        // Verification batch covers the seeded entries.
        assertEq(snap.verificationKeys.length, 2);
        assertEq(verificationSeeded.length, 2);
    }

    function test_getAllKeys_emptyVerificationKeysByDefault() public view {
        IQuipWallet.AllKeys memory snap = wallet.getAllKeys();
        assertEq(snap.verificationKeys.length, 0);
        assertEq(snap.transactionKeys.length, 5);
        assertEq(snap.recoveryKeys.length, 10);
    }
}
