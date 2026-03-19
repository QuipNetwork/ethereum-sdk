// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";

contract QuipWallet_addRecoveryKeys is QuipWalletTest {
    // Use a wallet with fewer initial recovery keys so we can test adding
    function _deployWalletWith3RecoveryKeys()
        internal
        returns (
            address walletAddr_,
            WOTSPlus.WinternitzAddress memory pubkey_,
            bytes32 privateKey_,
            WOTSPlus.WinternitzAddress[] memory rPubkeys_,
            bytes32[] memory rPrivateKeys_
        )
    {
        bytes32 vaultId = keccak256(abi.encodePacked("add-test-vault"));
        (pubkey_, privateKey_) = _generateKeyPair("add-test-vault");
        (rPubkeys_, rPrivateKeys_) = _generateRecoveryKeys("add-test-vault", 3);

        vm.prank(ALICE);
        walletAddr_ = factory.depositToWinternitz{value: INITIAL_DEPOSIT}(
            vaultId,
            payable(ALICE),
            pubkey_,
            rPubkeys_
        );
    }

    function test_addRecoveryKeys_addsKeysAndRotatesPqOwner() public {
        (
            address walletAddr_,
            WOTSPlus.WinternitzAddress memory pubkey_,
            bytes32 privateKey_,
            WOTSPlus.WinternitzAddress[] memory rPubkeys_,
        ) = _deployWalletWith3RecoveryKeys();

        QuipWallet w = QuipWallet(payable(walletAddr_));
        assertEq(w.getRecoveryKeyCount(), 3);

        // Add 2 more keys
        (WOTSPlus.WinternitzAddress[] memory newKeys, ) = _generateRecoveryKeys("add-new", 2);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq-add");

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(walletAddr_, pubkey_, nextPq, newKeys);
        WOTSPlus.WinternitzElements memory sig = _sign(privateKey_, msgHash);

        vm.prank(ALICE);
        w.addRecoveryKeys(nextPq, sig, newKeys);

        // Count increased
        assertEq(w.getRecoveryKeyCount(), 5);

        // New keys are in the set
        for (uint256 i = 0; i < newKeys.length; i++) {
            bytes32 keyHash = keccak256(abi.encode(newKeys[i].publicSeed, newKeys[i].publicKeyHash));
            assertTrue(w.isRecoveryKey(keyHash));
        }

        // Old keys still in the set
        for (uint256 i = 0; i < rPubkeys_.length; i++) {
            bytes32 keyHash = keccak256(abi.encode(rPubkeys_[i].publicSeed, rPubkeys_[i].publicKeyHash));
            assertTrue(w.isRecoveryKey(keyHash));
        }

        // pqOwner rotated
        (bytes32 publicSeed, bytes32 publicKeyHash) = w.pqOwner();
        assertEq(publicSeed, nextPq.publicSeed);
        assertEq(publicKeyHash, nextPq.publicKeyHash);
    }

    function test_addRecoveryKeys_revertsWhen_callerNotOwner() public {
        (
            address walletAddr_,
            WOTSPlus.WinternitzAddress memory pubkey_,
            bytes32 privateKey_,,
        ) = _deployWalletWith3RecoveryKeys();

        QuipWallet w = QuipWallet(payable(walletAddr_));

        (WOTSPlus.WinternitzAddress[] memory newKeys, ) = _generateRecoveryKeys("add-new", 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(walletAddr_, pubkey_, nextPq, newKeys);
        WOTSPlus.WinternitzElements memory sig = _sign(privateKey_, msgHash);

        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, BOB));
        w.addRecoveryKeys(nextPq, sig, newKeys);
    }

    function test_addRecoveryKeys_revertsWhen_invalidSignature() public {
        (
            address walletAddr_,,,
            ,
        ) = _deployWalletWith3RecoveryKeys();

        QuipWallet w = QuipWallet(payable(walletAddr_));

        (WOTSPlus.WinternitzAddress[] memory newKeys, ) = _generateRecoveryKeys("add-new", 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");

        // Sign wrong message
        (, bytes32 wrongKey) = _generateKeyPair("wrong");
        WOTSPlus.WinternitzElements memory badSig = _sign(wrongKey, keccak256("wrong"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        w.addRecoveryKeys(nextPq, badSig, newKeys);
    }

    function test_addRecoveryKeys_revertsWhen_newKeyIsZero() public {
        (
            address walletAddr_,
            WOTSPlus.WinternitzAddress memory pubkey_,
            bytes32 privateKey_,,
        ) = _deployWalletWith3RecoveryKeys();

        QuipWallet w = QuipWallet(payable(walletAddr_));

        WOTSPlus.WinternitzAddress[] memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(walletAddr_, pubkey_, nextPq, badKeys);
        WOTSPlus.WinternitzElements memory sig = _sign(privateKey_, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidPqOwner.selector);
        w.addRecoveryKeys(nextPq, sig, badKeys);
    }

    function test_addRecoveryKeys_revertsWhen_exceedsCap() public {
        (
            address walletAddr_,
            WOTSPlus.WinternitzAddress memory pubkey_,
            bytes32 privateKey_,,
        ) = _deployWalletWith3RecoveryKeys();

        QuipWallet w = QuipWallet(payable(walletAddr_));

        // Already has 3, adding 8 would exceed 10
        (WOTSPlus.WinternitzAddress[] memory tooMany, ) = _generateRecoveryKeys("overflow", 8);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");

        bytes32 msgHash = _buildAddRecoveryKeysMessageHash(walletAddr_, pubkey_, nextPq, tooMany);
        WOTSPlus.WinternitzElements memory sig = _sign(privateKey_, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(EnumerableSetLib.ExceedsCapacity.selector);
        w.addRecoveryKeys(nextPq, sig, tooMany);
    }
}
