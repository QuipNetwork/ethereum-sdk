// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipWallet_addRecoveryKeys is QuipWalletTest {
    function _deployWallet()
        internal
        returns (
            address walletAddr_,
            WOTSPlus.WinternitzAddress memory pubkey_,
            bytes32 privateKey_,
            WOTSPlus.WinternitzAddress[] memory rPubkeys_
        )
    {
        bytes32 vaultId = keccak256(abi.encodePacked("add-test-vault"));
        (pubkey_, privateKey_) = _generateKeyPair("add-test-vault");
        rPubkeys_ = _generateRecoveryKeys(privateKey_, 10);

        bytes memory payload = _encodeInitPayload(pubkey_, rPubkeys_);

        vm.prank(ALICE);
        walletAddr_ = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(
            vaultId,
            payable(ALICE),
            payload
        );
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_addRecoveryKeys_addsKeysAndRotatesPqOwner() public {
        (
            address walletAddr_,
            ,
            bytes32 privateKey_,
            WOTSPlus.WinternitzAddress[] memory rPubkeys_
        ) = _deployWallet();

        QuipWallet w = QuipWallet(payable(walletAddr_));
        assertEq(w.getRecoveryKeyCount(), 10);

        // Recover with first key to free a slot
        (WOTSPlus.WinternitzAddress memory postRecoveryPq, bytes32 postRecoverySigningKey) =
            _generateKeyPair(privateKey_);
        bytes32 recoverMsgHash = _buildRecoverWalletMessageHash(walletAddr_, rPubkeys_[0], postRecoveryPq);
        WOTSPlus.WinternitzElements memory recoverSig =
            _sign(_recoverySigningKey(privateKey_, 0), recoverMsgHash);

        vm.prank(ALICE);
        w.recoverWallet(rPubkeys_[0], postRecoveryPq, recoverSig);
        assertEq(w.getRecoveryKeyCount(), 9);

        // Add 1 new key
        bytes32 addBase = keccak256(abi.encodePacked(privateKey_, "add"));
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(addBase, 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) =
            _generateKeyPair(keccak256(abi.encodePacked(privateKey_, uint256(1))));

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(walletAddr_, postRecoveryPq, nextPq, newKeys);
        WOTSPlus.WinternitzElements memory sig = _sign(postRecoverySigningKey, msgHash);

        vm.prank(ALICE);
        w.addRecoveryKeys(nextPq, sig, newKeys);

        assertEq(w.getRecoveryKeyCount(), 10);

        bytes32 keyHash = keccak256(abi.encode(newKeys[0].publicSeed, newKeys[0].publicKeyHash));
        assertTrue(w.isRecoveryKey(keyHash));

        (bytes32 publicSeed, bytes32 publicKeyHash) = w.pqOwner();
        assertEq(publicSeed, nextPq.publicSeed);
        assertEq(publicKeyHash, nextPq.publicKeyHash);
    }

    function test_addRecoveryKeys_emitsRecoveryKeysAdded() public {
        (
            address walletAddr_,
            ,
            bytes32 privateKey_,
            WOTSPlus.WinternitzAddress[] memory rPubkeys_
        ) = _deployWallet();

        QuipWallet w = QuipWallet(payable(walletAddr_));

        // Recover with first key to free a slot
        (WOTSPlus.WinternitzAddress memory postRecoveryPq, bytes32 postRecoverySigningKey) =
            _generateKeyPair(privateKey_);
        bytes32 recoverMsgHash = _buildRecoverWalletMessageHash(walletAddr_, rPubkeys_[0], postRecoveryPq);
        WOTSPlus.WinternitzElements memory recoverSig =
            _sign(_recoverySigningKey(privateKey_, 0), recoverMsgHash);

        vm.prank(ALICE);
        w.recoverWallet(rPubkeys_[0], postRecoveryPq, recoverSig);

        // Add 1 new key
        bytes32 addBase = keccak256(abi.encodePacked(privateKey_, "add-event"));
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(addBase, 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) =
            _generateKeyPair(keccak256(abi.encodePacked(privateKey_, uint256(1))));

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(walletAddr_, postRecoveryPq, nextPq, newKeys);
        WOTSPlus.WinternitzElements memory sig = _sign(postRecoverySigningKey, msgHash);

        vm.prank(ALICE);
        vm.recordLogs();
        w.addRecoveryKeys(nextPq, sig, newKeys);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.RecoveryKeysAdded.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "RecoveryKeysAdded event not emitted");
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_addRecoveryKeys_revertsWhen_callerNotOwner() public {
        (
            address walletAddr_,
            WOTSPlus.WinternitzAddress memory pubkey_,
            bytes32 privateKey_,
        ) = _deployWallet();

        QuipWallet w = QuipWallet(payable(walletAddr_));

        bytes32 addBase = keccak256(abi.encodePacked(privateKey_, "add"));
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(addBase, 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair(privateKey_);

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(walletAddr_, pubkey_, nextPq, newKeys);
        WOTSPlus.WinternitzElements memory sig = _sign(privateKey_, msgHash);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        w.addRecoveryKeys(nextPq, sig, newKeys);
    }

    function test_addRecoveryKeys_revertsWhen_invalidSignature() public {
        (
            address walletAddr_,,,
        ) = _deployWallet();

        QuipWallet w = QuipWallet(payable(walletAddr_));

        bytes32 addBase = keccak256(abi.encodePacked(bytes32("wrong"), "add"));
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(addBase, 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("wrong");

        (, bytes32 wrongKey) = _generateKeyPair("wrong");
        WOTSPlus.WinternitzElements memory badSig = _sign(wrongKey, keccak256("wrong"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        w.addRecoveryKeys(nextPq, badSig, newKeys);
    }

    function test_addRecoveryKeys_revertsWhen_newKeyIsZero() public {
        (
            address walletAddr_,
            ,
            bytes32 privateKey_,
            WOTSPlus.WinternitzAddress[] memory rPubkeys_
        ) = _deployWallet();

        QuipWallet w = QuipWallet(payable(walletAddr_));

        // Recover to free a slot first
        (WOTSPlus.WinternitzAddress memory currentPq, bytes32 currentPqSigningKey) =
            _generateKeyPair(privateKey_);
        bytes32 recoverMsgHash = _buildRecoverWalletMessageHash(walletAddr_, rPubkeys_[0], currentPq);
        WOTSPlus.WinternitzElements memory recoverSig =
            _sign(_recoverySigningKey(privateKey_, 0), recoverMsgHash);

        vm.prank(ALICE);
        w.recoverWallet(rPubkeys_[0], currentPq, recoverSig);

        WOTSPlus.WinternitzAddress[] memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        (WOTSPlus.WinternitzAddress memory nextPq,) =
            _generateKeyPair(keccak256(abi.encodePacked(privateKey_, uint256(1))));

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(walletAddr_, currentPq, nextPq, badKeys);
        WOTSPlus.WinternitzElements memory sig = _sign(currentPqSigningKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        w.addRecoveryKeys(nextPq, sig, badKeys);
    }

    function test_addRecoveryKeys_revertsWhen_exceedsCap() public {
        (
            address walletAddr_,
            WOTSPlus.WinternitzAddress memory pubkey_,
            bytes32 privateKey_,
        ) = _deployWallet();

        QuipWallet w = QuipWallet(payable(walletAddr_));

        // Already has 10, adding 1 would exceed cap
        bytes32 addBase = keccak256(abi.encodePacked(privateKey_, "add"));
        WOTSPlus.WinternitzAddress[] memory extraKey = _generateRecoveryKeys(addBase, 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair(privateKey_);

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(walletAddr_, pubkey_, nextPq, extraKey);
        WOTSPlus.WinternitzElements memory sig = _sign(privateKey_, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(EnumerableSetLib.ExceedsCapacity.selector);
        w.addRecoveryKeys(nextPq, sig, extraKey);
    }

    function test_addRecoveryKeys_revertsWhen_nextPqOwnerSeedIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        WOTSPlus.WinternitzAddress[] memory newKeys = new WOTSPlus.WinternitzAddress[](1);
        newKeys[0] = WOTSPlus.WinternitzAddress({publicSeed: bytes32("a"), publicKeyHash: bytes32("b")});

        WOTSPlus.WinternitzElements memory dummySig = _sign(alicePrivateKey, keccak256("dummy"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.addRecoveryKeys(zeroPq, dummySig, newKeys);
    }

    function test_addRecoveryKeys_revertsWhen_nextPqOwnerHashIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzAddress[] memory newKeys = new WOTSPlus.WinternitzAddress[](1);
        newKeys[0] = WOTSPlus.WinternitzAddress({publicSeed: bytes32("a"), publicKeyHash: bytes32("b")});

        WOTSPlus.WinternitzElements memory dummySig = _sign(alicePrivateKey, keccak256("dummy"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.addRecoveryKeys(zeroPq, dummySig, newKeys);
    }

    function test_addRecoveryKeys_revertsWhen_emptyArray() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-empty");
        WOTSPlus.WinternitzAddress[] memory emptyKeys = new WOTSPlus.WinternitzAddress[](0);

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, emptyKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.EmptyRecoveryKeys.selector);
        wallet.addRecoveryKeys(nextPq, sig, emptyKeys);
    }

    function test_addRecoveryKeys_revertsWhen_duplicateKeyInBatch() public {
        // Use default wallet — recover keys[0] and keys[1] to free 2 slots
        (WOTSPlus.WinternitzAddress memory pq1, bytes32 pq1Key) =
            _generateKeyPair("dup-batch-pq1");
        bytes32 recoverMsg1 = _buildRecoverWalletMessageHash(
            address(wallet), recoveryPubkeys[0], pq1
        );
        WOTSPlus.WinternitzElements memory recoverSig1 =
            _sign(_recoverySigningKey(alicePrivateKey, 0), recoverMsg1);

        vm.prank(ALICE);
        wallet.recoverWallet(recoveryPubkeys[0], pq1, recoverSig1);

        (WOTSPlus.WinternitzAddress memory pq2, bytes32 pq2Key) =
            _generateKeyPair("dup-batch-pq2");
        bytes32 recoverMsg2 = _buildRecoverWalletMessageHash(
            address(wallet), recoveryPubkeys[1], pq2
        );
        WOTSPlus.WinternitzElements memory recoverSig2 =
            _sign(_recoverySigningKey(alicePrivateKey, 1), recoverMsg2);

        vm.prank(ALICE);
        wallet.recoverWallet(recoveryPubkeys[1], pq2, recoverSig2);

        // Add 2 identical keys
        WOTSPlus.WinternitzAddress[] memory dupKeys = new WOTSPlus.WinternitzAddress[](2);
        (dupKeys[0],) = _generateKeyPair("dup-new-key");
        dupKeys[1] = dupKeys[0]; // duplicate!

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("dup-batch-next");
        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(wallet), pq2, nextPq, dupKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(pq2Key, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateRecoveryKey.selector);
        wallet.addRecoveryKeys(nextPq, sig, dupKeys);
    }

    function test_addRecoveryKeys_revertsWhen_duplicateOfExistingKey() public {
        // Use default wallet — recover key[0] to free a slot
        (WOTSPlus.WinternitzAddress memory postRecoveryPq, bytes32 postRecoveryKey) =
            _generateKeyPair("dup-existing-pq");
        bytes32 recoverMsg = _buildRecoverWalletMessageHash(
            address(wallet), recoveryPubkeys[0], postRecoveryPq
        );
        WOTSPlus.WinternitzElements memory recoverSig =
            _sign(_recoverySigningKey(alicePrivateKey, 0), recoverMsg);

        vm.prank(ALICE);
        wallet.recoverWallet(recoveryPubkeys[0], postRecoveryPq, recoverSig);

        // Try to add key[1] which already exists in the set
        WOTSPlus.WinternitzAddress[] memory existingKey = new WOTSPlus.WinternitzAddress[](1);
        existingKey[0] = recoveryPubkeys[1]; // already in set!

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("dup-existing-next");
        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(
            address(wallet), postRecoveryPq, nextPq, existingKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(postRecoveryKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateRecoveryKey.selector);
        wallet.addRecoveryKeys(nextPq, sig, existingKey);
    }
}
