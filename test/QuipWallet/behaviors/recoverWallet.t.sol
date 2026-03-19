// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_recoverWallet is QuipWalletTest {
    function test_recoverWallet_updatesOwnerAndConsumesKey() public {
        (WOTSPlus.WinternitzAddress memory newPq,) = _generateKeyPair("new-pq-after-recovery");

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = recoveryPrivateKeys[0];

        bytes32 msgHash = _buildRecoverWalletMessageHash(address(wallet), rKey, newPq);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        uint256 countBefore = wallet.getRecoveryKeyCount();

        vm.prank(ALICE);
        wallet.recoverWallet(rKey, newPq, sig);

        // pqOwner updated
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, newPq.publicSeed);
        assertEq(publicKeyHash, newPq.publicKeyHash);

        // Recovery key consumed
        assertEq(wallet.getRecoveryKeyCount(), countBefore - 1);
        bytes32 keyHash = keccak256(abi.encode(rKey.publicSeed, rKey.publicKeyHash));
        assertFalse(wallet.isRecoveryKey(keyHash));
    }

    function test_recoverWallet_revertsWhen_callerNotOwner() public {
        (WOTSPlus.WinternitzAddress memory newPq,) = _generateKeyPair("new-pq");

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = recoveryPrivateKeys[0];

        bytes32 msgHash = _buildRecoverWalletMessageHash(address(wallet), rKey, newPq);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, BOB));
        wallet.recoverWallet(rKey, newPq, sig);
    }

    function test_recoverWallet_revertsWhen_keyNotInSet() public {
        (WOTSPlus.WinternitzAddress memory newPq,) = _generateKeyPair("new-pq");
        (WOTSPlus.WinternitzAddress memory fakeKey, bytes32 fakePrivKey) = _generateKeyPair("fake-recovery");

        bytes32 msgHash = _buildRecoverWalletMessageHash(address(wallet), fakeKey, newPq);
        WOTSPlus.WinternitzElements memory sig = _sign(fakePrivKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.RecoveryKeyNotFound.selector);
        wallet.recoverWallet(fakeKey, newPq, sig);
    }

    function test_recoverWallet_revertsWhen_newPqOwnerIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = recoveryPrivateKeys[0];

        bytes32 msgHash = _buildRecoverWalletMessageHash(address(wallet), rKey, zeroPq);
        WOTSPlus.WinternitzElements memory sig = _sign(rPrivKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidPqOwner.selector);
        wallet.recoverWallet(rKey, zeroPq, sig);
    }

    function test_recoverWallet_revertsWhen_invalidSignature() public {
        (WOTSPlus.WinternitzAddress memory newPq,) = _generateKeyPair("new-pq");

        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];
        bytes32 rPrivKey = recoveryPrivateKeys[0];

        // Sign a wrong message
        bytes32 wrongMsgHash = keccak256("wrong message");
        WOTSPlus.WinternitzElements memory badSig = _sign(rPrivKey, wrongMsgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.recoverWallet(rKey, newPq, badSig);
    }

    function test_recoverWallet_multipleIndependentRecoveries() public {
        // First recovery
        (WOTSPlus.WinternitzAddress memory newPq1,) = _generateKeyPair("new-pq-1");
        WOTSPlus.WinternitzAddress memory rKey0 = recoveryPubkeys[0];
        bytes32 msgHash1 = _buildRecoverWalletMessageHash(address(wallet), rKey0, newPq1);
        WOTSPlus.WinternitzElements memory sig1 = _sign(recoveryPrivateKeys[0], msgHash1);

        vm.prank(ALICE);
        wallet.recoverWallet(rKey0, newPq1, sig1);

        assertEq(wallet.getRecoveryKeyCount(), 9);

        // Second recovery with a different key
        (WOTSPlus.WinternitzAddress memory newPq2,) = _generateKeyPair("new-pq-2");
        WOTSPlus.WinternitzAddress memory rKey1 = recoveryPubkeys[1];
        bytes32 msgHash2 = _buildRecoverWalletMessageHash(address(wallet), rKey1, newPq2);
        WOTSPlus.WinternitzElements memory sig2 = _sign(recoveryPrivateKeys[1], msgHash2);

        vm.prank(ALICE);
        wallet.recoverWallet(rKey1, newPq2, sig2);

        assertEq(wallet.getRecoveryKeyCount(), 8);
    }

    function test_recoverWallet_walletOperationsWorkWithNewPqOwner() public {
        // Recover
        (WOTSPlus.WinternitzAddress memory newPq, bytes32 newPqPrivKey) = _generateKeyPair("new-pq-for-ops");
        WOTSPlus.WinternitzAddress memory rKey = recoveryPubkeys[0];

        bytes32 msgHash = _buildRecoverWalletMessageHash(address(wallet), rKey, newPq);
        WOTSPlus.WinternitzElements memory sig = _sign(recoveryPrivateKeys[0], msgHash);

        vm.prank(ALICE);
        wallet.recoverWallet(rKey, newPq, sig);

        // Now do a transfer with the new pqOwner
        uint256 transferAmount = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-after-recovery");

        bytes32 transferMsgHash = _buildTransferMessageHash(
            address(wallet), newPq, nextPq, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory transferSig = _sign(newPqPrivKey, transferMsgHash);

        uint256 bobBalBefore = BOB.balance;

        vm.prank(ALICE);
        wallet.transferWithWinternitz(nextPq, transferSig, payable(BOB), transferAmount);

        assertEq(BOB.balance, bobBalBefore + transferAmount);
    }
}
