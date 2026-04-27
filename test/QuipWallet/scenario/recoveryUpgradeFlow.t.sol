// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

/// @title Recovery Upgrade Flow Scenario Test
/// @dev Emergency upgrade via recovery key when PQ key is compromised.
///      Flow: recoveryUpgrade (no PQ rotation) → recoverWallet (fix PQ key) → resume.
contract QuipWallet_recoveryUpgradeFlow is QuipWalletTest {
    QuipWallet public newImpl;

    function setUp() public override {
        super.setUp();
        newImpl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(newImpl));
    }

    function _buildRecoveryUpgradePayload(
        WOTSPlus.WinternitzAddress memory rKey,
        WOTSPlus.WinternitzAddress memory newRKey,
        WOTSPlus.WinternitzElements memory sig,
        address impl,
        bytes32 verifierSeed
    ) internal view returns (bytes memory) {
        (
            WOTSPlus.WinternitzAddress memory vPub,
            bytes32 vPriv
        ) = _generateKeyPair(verifierSeed);
        bytes32 vHash = Codec.verificationDigest(
            address(wallet),
            block.chainid,
            impl,
            vPub.publicSeed,
            vPub.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory vSig = _sign(vPriv, vHash);

        return
            Codec.encodeRecoveryUpgrade(rKey, newRKey, sig, vPub, vSig);
    }

    /// @dev Emergency upgrade via recovery key → recoverWallet → resume operations.
    function test_simulation_recoveryUpgradeFlow() public {
        // Step 1: Simulate PQ key compromised — we still have recovery keys.
        //         Use recovery key 0 to perform emergency upgrade; the key
        //         rotates in place so the recovery pool stays full.
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);
        (WOTSPlus.WinternitzAddress memory newRKey, ) = _generateKeyPair(
            "recovery-upgrade-new-rkey"
        );

        bytes32 msgHash = _buildRecoveryUpgradeMessageHash(
            address(wallet),
            address(newImpl),
            rKey,
            newRKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        bytes memory payload = _buildRecoveryUpgradePayload(
            rKey,
            newRKey,
            sig,
            address(newImpl),
            "recovery-upgrade-verifier"
        );

        uint256 txnCountBefore = wallet.keyCount(Codec.KeyType.Transaction);
        bool aliceActiveBefore = wallet.isKey(Codec.KeyType.Transaction, alicePubkey);
        uint256 balBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.recoveryUpgrade(address(newImpl), payload);

        // Step 2: Verify post-upgrade state
        // 2a: Implementation changed
        assertEq(
            wallet.version(),
            factory.getVettedCodeIndex(address(newImpl).codehash)
        );

        // 2b: Transaction keys NOT rotated (critical: recoveryUpgrade doesn't rotate)
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), txnCountBefore);
        assertEq(wallet.isKey(Codec.KeyType.Transaction, alicePubkey), aliceActiveBefore);

        // 2c: Recovery key 0 consumed and replaced in place — count preserved.
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, rKey));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, newRKey));

        // 2d: Balance and owner preserved
        assertEq(address(wallet).balance, balBefore);
        assertEq(wallet.owner(), ALICE);

        // Step 3: Fix the compromised PQ key via recoverWallet (using recovery key 1)
        (
            WOTSPlus.WinternitzAddress memory newPqOwner,
            bytes32 newPqPrivKey
        ) = _generateKeyPair("new-pq-after-recovery-upgrade");
        (
            WOTSPlus.WinternitzAddress memory newRk,
        ) = _generateKeyPair("new-rk-after-recovery-upgrade");

        WOTSPlus.WinternitzAddress memory rKey1 = recoveryPubkeys[1];
        bytes32 rPrivKey1 = _recoverySigningKey(alicePrivateKey, 1);

        bytes32 recoverHash = _buildRecoverWalletMessageHash(
            address(wallet),
            rKey1,
            newRk,
            newPqOwner
        );
        WOTSPlus.WinternitzElements memory recoverSig = _sign(
            rPrivKey1,
            recoverHash
        );

        vm.prank(ALICE);
        wallet.recoverWallet(
            Codec.encodeRecoverWallet(rKey1, newRk, newPqOwner, recoverSig)
        );

        // PQ key now fixed; recoverWallet rotated recovery key 1 in-place (size
        // preserved at 10) and reseeded the transaction keyset.
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, newPqOwner));
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, rKey1));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, newRk));
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

        // Step 4: Resume normal operations with the new key
        (WOTSPlus.WinternitzAddress memory postPq, ) = _generateKeyPair(
            "post-recovery-upgrade-key"
        );
        uint256 fee = wallet.getExecuteFee();
        bytes32 execHash = _buildExecuteMessageHash(
            address(wallet),
            newPqOwner,
            postPq,
            BOB,
            0.05 ether,
            "",
            fee
        );
        WOTSPlus.WinternitzElements memory execSig = _sign(
            newPqPrivKey,
            execHash
        );

        uint256 bobBal = BOB.balance;
        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                newPqOwner,
                postPq,
                execSig,
                BOB,
                0.05 ether,
                ""
            )
        );
        assertEq(BOB.balance, bobBal + 0.05 ether);
    }
}
