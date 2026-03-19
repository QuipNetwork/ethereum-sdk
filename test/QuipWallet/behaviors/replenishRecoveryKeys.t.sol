// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_replenishRecoveryKeys is QuipWalletTest {
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

    function test_replenishRecoveryKeys_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
            keccak256(abi.encodePacked(alicePrivateKey, "replenish")), 3);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");

        bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, BOB));
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
        vm.expectRevert(IQuipWallet.InvalidPqOwner.selector);
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
}
