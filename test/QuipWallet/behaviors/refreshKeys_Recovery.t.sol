// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

contract QuipWallet_refreshKeys_Recovery is QuipWalletTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_refreshKeys_Recovery_clearsAndAddsNewKeys() public {
        // wallet has 10 recovery keys from setUp
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

        bytes32 replenishBase = keccak256(
            abi.encodePacked(alicePrivateKey, "replenish")
        );
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            replenishBase,
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq-replenish"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, newKeys)
        );

        // Count is now 5
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 5);

        // Old keys are gone
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }

        // New keys are present
        for (uint256 i = 0; i < newKeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, newKeys[i]));
        }

        // pqOwner rotated
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
    }

    function test_refreshKeys_Recovery_emitsKeysRefreshed() public {
        bytes32 replenishBase = keccak256(
            abi.encodePacked(alicePrivateKey, "replenish-event")
        );
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            replenishBase,
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq-event"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, newKeys)
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.KeysRefreshed.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "KeysRefreshed event not emitted");
    }

    function test_refreshKeys_Recovery_newKeysWorkForRecovery() public {
        bytes32 replenishBase = keccak256(
            abi.encodePacked(alicePrivateKey, "replenish")
        );
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            replenishBase,
            5
        );
        (
            WOTSPlus.WinternitzAddress memory nextPq,
            bytes32 nextPqPrivKey
        ) = _generateKeyPair("next-pq-replenish");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, newKeys)
        );

        // Now use the first new recovery key
        (WOTSPlus.WinternitzAddress memory recoveredPq, ) = _generateKeyPair(
            "recovered-pq"
        );

        bytes32 recoverMsg = _buildRecoverWalletMessageHash(
            address(wallet),
            newKeys[0],
            recoveredPq
        );
        WOTSPlus.WinternitzElements memory recoverSig = _sign(
            _recoverySigningKey(replenishBase, 0),
            recoverMsg
        );

        vm.prank(ALICE);
        wallet.recoverWallet(
            Codec.encodeRecoverWallet(newKeys[0], recoveredPq, recoverSig)
        );

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, recoveredPq));
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 4);
    }

    function test_refreshKeys_Recovery_exactlyMaxKeys() public {
        bytes32 replenishBase = keccak256(
            abi.encodePacked(alicePrivateKey, "max-keys")
        );
        WOTSPlus.WinternitzAddress[] memory maxKeys = _generateRecoveryKeys(
            replenishBase,
            10
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq-max"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            maxKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, maxKeys)
        );

        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_refreshKeys_Recovery_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256(abi.encodePacked(alicePrivateKey, "replenish")),
            3
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, newKeys)
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_invalidSignature() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256(abi.encodePacked(alicePrivateKey, "replenish")),
            3
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq"
        );

        WOTSPlus.WinternitzElements memory badSig = _sign(
            alicePrivateKey,
            keccak256("wrong")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, badSig, newKeys)
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_newKeyIsZero() public {
        WOTSPlus.WinternitzAddress[]
            memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            badKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, badKeys)
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_tooManyNewKeys() public {
        WOTSPlus.WinternitzAddress[] memory tooMany = _generateRecoveryKeys(
            keccak256(abi.encodePacked(alicePrivateKey, "overflow")),
            11
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            tooMany
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ExceedsCapacity.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, tooMany)
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_nextPqOwnerSeedIsZero()
        public
    {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("replenish"),
            3
        );
        WOTSPlus.WinternitzElements memory dummySig = _sign(
            alicePrivateKey,
            keccak256("dummy")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, zeroPq, dummySig, newKeys)
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_nextPqOwnerHashIsZero()
        public
    {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256("replenish"),
            3
        );
        WOTSPlus.WinternitzElements memory dummySig = _sign(
            alicePrivateKey,
            keccak256("dummy")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, zeroPq, dummySig, newKeys)
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_emptyArray() public {
        WOTSPlus.WinternitzAddress[]
            memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq-empty"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            emptyKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.EmptyKeys.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, emptyKeys)
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_duplicateKeyInBatch()
        public
    {
        WOTSPlus.WinternitzAddress[]
            memory dupKeys = new WOTSPlus.WinternitzAddress[](2);
        (dupKeys[0], ) = _generateKeyPair("dup-key");
        dupKeys[1] = dupKeys[0]; // duplicate

        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq-dup"
        );
        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            dupKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, dupKeys)
        );
    }

    function test_refreshKeys_Recovery_oldKeysInvalidAfterReplenish() public {
        bytes32 replenishBase = keccak256(
            abi.encodePacked(alicePrivateKey, "replenish-old")
        );
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            replenishBase,
            5
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "next-pq-old-check"
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, nextPq, sig, newKeys)
        );

        // Try recovery with old key[0] — should fail
        WOTSPlus.WinternitzAddress memory oldKey = recoveryPubkeys[0];
        (WOTSPlus.WinternitzAddress memory recoveredPq, ) = _generateKeyPair(
            "recovered-old"
        );
        bytes32 rPrivKey = _recoverySigningKey(alicePrivateKey, 0);
        bytes32 recoverMsg = _buildRecoverWalletMessageHash(
            address(wallet),
            oldKey,
            recoveredPq
        );
        WOTSPlus.WinternitzElements memory recoverSig = _sign(
            rPrivKey,
            recoverMsg
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.recoverWallet(
            Codec.encodeRecoverWallet(oldKey, recoveredPq, recoverSig)
        );
    }

    function test_refreshKeys_Recovery_revertsWhen_pqOwnerReuse() public {
        bytes32 replenishBase = keccak256(
            abi.encodePacked(alicePrivateKey, "replenish-reuse")
        );
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            replenishBase,
            5
        );

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            alicePubkey,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, alicePubkey, alicePubkey, sig, newKeys)
        );
    }
}
