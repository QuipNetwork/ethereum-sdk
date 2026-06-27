// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";

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
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, BOB));
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
        vm.expectRevert(IQuipWallet.InvalidPqOwner.selector);
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
}
