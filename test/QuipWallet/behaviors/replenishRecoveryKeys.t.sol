// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipWallet_replenishRecoveryKeys is QuipWalletTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_replenishRecoveryKeys_clearsAndAddsNewKeys() public {
        // wallet has 10 recovery keys from setUp
        assertEq(wallet.getRecoveryKeyCount(), 10);

        bytes32 replenishBase = keccak256(abi.encodePacked(alicePrivateKey, "replenish"));
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(replenishBase, 5);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-replenish");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.replenishRecoveryKeys(nextPq, sig, newKeys);

        // Count is now 5
        assertEq(wallet.getRecoveryKeyCount(), 5);

        // Old keys are gone
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            bytes32 keyHash = keccak256(abi.encode(recoveryPubkeys[i].publicSeed, recoveryPubkeys[i].publicKeyHash));
            assertFalse(wallet.isRecoveryKey(keyHash));
        }

        // New keys are present
        for (uint256 i = 0; i < newKeys.length; i++) {
            bytes32 keyHash = keccak256(abi.encode(newKeys[i].publicSeed, newKeys[i].publicKeyHash));
            assertTrue(wallet.isRecoveryKey(keyHash));
        }

        // pqOwner rotated
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, nextPq.publicSeed);
        assertEq(publicKeyHash, nextPq.publicKeyHash);
    }

    function test_replenishRecoveryKeys_emitsRecoveryKeysReplenished() public {
        bytes32 replenishBase = keccak256(abi.encodePacked(alicePrivateKey, "replenish-event"));
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(replenishBase, 5);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-event");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.replenishRecoveryKeys(nextPq, sig, newKeys);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.RecoveryKeysReplenished.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "RecoveryKeysReplenished event not emitted");
    }

    function test_replenishRecoveryKeys_newKeysWorkForRecovery() public {
        bytes32 replenishBase = keccak256(abi.encodePacked(alicePrivateKey, "replenish"));
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(replenishBase, 5);
        (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPqPrivKey) = _generateKeyPair("next-pq-replenish");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.replenishRecoveryKeys(nextPq, sig, newKeys);

        // Now use the first new recovery key
        (WOTSPlus.WinternitzAddress memory recoveredPq,) = _generateKeyPair("recovered-pq");

        bytes32 recoverMsg = _buildRecoverWalletMessageHash(address(wallet), newKeys[0], recoveredPq);
        WOTSPlus.WinternitzElements memory recoverSig = _sign(_recoverySigningKey(replenishBase, 0), recoverMsg);

        vm.prank(ALICE);
        wallet.recoverWallet(newKeys[0], recoveredPq, recoverSig);

        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, recoveredPq.publicSeed);
        assertEq(publicKeyHash, recoveredPq.publicKeyHash);
        assertEq(wallet.getRecoveryKeyCount(), 4);
    }

    function test_replenishRecoveryKeys_exactlyMaxKeys() public {
        bytes32 replenishBase = keccak256(abi.encodePacked(alicePrivateKey, "max-keys"));
        WOTSPlus.WinternitzAddress[] memory maxKeys = _generateRecoveryKeys(replenishBase, 10);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-max");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, maxKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.replenishRecoveryKeys(nextPq, sig, maxKeys);

        assertEq(wallet.getRecoveryKeyCount(), 10);
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_replenishRecoveryKeys_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256(abi.encodePacked(alicePrivateKey, "replenish")), 3);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.replenishRecoveryKeys(nextPq, sig, newKeys);
    }

    function test_replenishRecoveryKeys_revertsWhen_invalidSignature() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256(abi.encodePacked(alicePrivateKey, "replenish")), 3);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");

        WOTSPlus.WinternitzElements memory badSig = _sign(alicePrivateKey, keccak256("wrong"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.replenishRecoveryKeys(nextPq, badSig, newKeys);
    }

    function test_replenishRecoveryKeys_revertsWhen_newKeyIsZero() public {
        WOTSPlus.WinternitzAddress[] memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, badKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.replenishRecoveryKeys(nextPq, sig, badKeys);
    }

    function test_replenishRecoveryKeys_revertsWhen_tooManyNewKeys() public {
        WOTSPlus.WinternitzAddress[] memory tooMany = _generateRecoveryKeys(
            keccak256(abi.encodePacked(alicePrivateKey, "overflow")), 11);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, tooMany
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.RecoveryKeyLimitExceeded.selector);
        wallet.replenishRecoveryKeys(nextPq, sig, tooMany);
    }

    function test_replenishRecoveryKeys_revertsWhen_nextPqOwnerSeedIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(keccak256("replenish"), 3);
        WOTSPlus.WinternitzElements memory dummySig = _sign(alicePrivateKey, keccak256("dummy"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.replenishRecoveryKeys(zeroPq, dummySig, newKeys);
    }

    function test_replenishRecoveryKeys_revertsWhen_nextPqOwnerHashIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(keccak256("replenish"), 3);
        WOTSPlus.WinternitzElements memory dummySig = _sign(alicePrivateKey, keccak256("dummy"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.replenishRecoveryKeys(zeroPq, dummySig, newKeys);
    }

    function test_replenishRecoveryKeys_revertsWhen_emptyArray() public {
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-empty");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, emptyKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.EmptyRecoveryKeys.selector);
        wallet.replenishRecoveryKeys(nextPq, sig, emptyKeys);
    }

    function test_replenishRecoveryKeys_revertsWhen_duplicateKeyInBatch() public {
        WOTSPlus.WinternitzAddress[] memory dupKeys = new WOTSPlus.WinternitzAddress[](2);
        (dupKeys[0],) = _generateKeyPair("dup-key");
        dupKeys[1] = dupKeys[0]; // duplicate

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-dup");
        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, dupKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateRecoveryKey.selector);
        wallet.replenishRecoveryKeys(nextPq, sig, dupKeys);
    }

    function test_replenishRecoveryKeys_oldKeysInvalidAfterReplenish() public {
        bytes32 replenishBase = keccak256(abi.encodePacked(alicePrivateKey, "replenish-old"));
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(replenishBase, 5);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-old-check");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.replenishRecoveryKeys(nextPq, sig, newKeys);

        // Try recovery with old key[0] — should fail
        WOTSPlus.WinternitzAddress memory oldKey = recoveryPubkeys[0];
        (WOTSPlus.WinternitzAddress memory recoveredPq,) = _generateKeyPair("recovered-old");
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);
        bytes32 recoverMsg = _buildRecoverWalletMessageHash(address(wallet), oldKey, recoveredPq);
        WOTSPlus.WinternitzElements memory recoverSig = _sign(rPrivKey, recoverMsg);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.RecoveryKeyNotFound.selector);
        wallet.recoverWallet(oldKey, recoveredPq, recoverSig);
    }

    function test_replenishRecoveryKeys_revertsWhen_pqOwnerReuse() public {
        bytes32 replenishBase = keccak256(abi.encodePacked(alicePrivateKey, "replenish-reuse"));
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(replenishBase, 5);

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, alicePubkey, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.PqOwnerReuse.selector);
        wallet.replenishRecoveryKeys(alicePubkey, sig, newKeys);
    }
}
