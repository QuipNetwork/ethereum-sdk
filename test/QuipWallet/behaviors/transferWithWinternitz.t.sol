// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_transferWithWinternitz is QuipWalletTest {
    function test_transferWithWinternitz_transfersFunds() public {
        uint256 transferAmount = 0.5 ether;

        // Generate next keypair
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        // Build and sign message
        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 bobBalBefore = BOB.balance;
        uint256 walletBalBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.transferWithWinternitz(nextPubkey, sig, payable(BOB), transferAmount);

        // Verify balances
        assertEq(address(wallet).balance, walletBalBefore - transferAmount);
        assertEq(BOB.balance, bobBalBefore + transferAmount);

        // Verify pqOwner updated
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, nextPubkey.publicSeed);
        assertEq(publicKeyHash, nextPubkey.publicKeyHash);
    }

    function test_transferWithWinternitz_emitsPqTransferEvent() public {
        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.transferWithWinternitz(nextPubkey, sig, payable(BOB), transferAmount);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("pqTransfer(uint256,uint256,(bytes32,bytes32),(bytes32,bytes32),address)")) {
                found = true;
                break;
            }
        }
        assertTrue(found, "pqTransfer event not emitted");
    }

    function test_transferWithWinternitz_walletToWalletAndWithdraw() public {
        // Deploy a second wallet for BOB
        (
            address bobWalletAddr,
            WOTSPlus.WinternitzAddress memory bobPubkey,
            bytes32 bobPrivateKey,
        ) = _createWallet(BOB, "bob-vault-1", 0);

        uint256 transferAmount = 0.5 ether;

        // Transfer from Alice's wallet to Bob's wallet
        (WOTSPlus.WinternitzAddress memory aliceNextPubkey,) = _generateKeyPair("alice-next-1");
        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, aliceNextPubkey, bobWalletAddr, transferAmount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.transferWithWinternitz(aliceNextPubkey, sig, payable(bobWalletAddr), transferAmount);

        assertEq(bobWalletAddr.balance, transferAmount);

        // Bob withdraws from his wallet to his own address
        QuipWallet bobWallet = QuipWallet(payable(bobWalletAddr));
        (WOTSPlus.WinternitzAddress memory bobNextPubkey,) = _generateKeyPair("bob-next-1");
        bytes32 withdrawMsgHash = _buildTransferMessageHash(
            bobWalletAddr, bobPubkey, bobNextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory withdrawSig = _sign(bobPrivateKey, withdrawMsgHash);

        uint256 bobBalBefore = BOB.balance;

        vm.prank(BOB);
        bobWallet.transferWithWinternitz(bobNextPubkey, withdrawSig, payable(BOB), transferAmount);

        assertEq(bobWalletAddr.balance, 0);
        assertEq(BOB.balance, bobBalBefore + transferAmount);
    }

    function test_transferWithWinternitz_collectsFees() public {
        // Set transfer fee
        vm.prank(ADMIN);
        factory.setTransferFee(TRANSFER_FEE);

        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 factoryBalBefore = address(factory).balance;
        uint256 bobBalBefore = BOB.balance;

        vm.prank(ALICE);
        wallet.transferWithWinternitz{value: TRANSFER_FEE}(
            nextPubkey, sig, payable(BOB), transferAmount
        );

        // Fee goes to factory
        assertEq(address(factory).balance, factoryBalBefore + TRANSFER_FEE);
        // Bob gets the transfer amount
        assertEq(BOB.balance, bobBalBefore + transferAmount);
    }

    function test_transferWithWinternitz_revertsWhen_insufficientBalance() public {
        vm.prank(ADMIN);
        factory.setTransferFee(TRANSFER_FEE);

        // Transfer the full wallet balance — leaves nothing for the fee
        uint256 transferAmount = INITIAL_DEPOSIT;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(
            IQuipWallet.InsufficientBalance.selector,
            transferAmount + TRANSFER_FEE,
            INITIAL_DEPOSIT
        ));
        wallet.transferWithWinternitz(nextPubkey, sig, payable(BOB), transferAmount);
    }

    function test_transferWithWinternitz_revertsWhen_callerNotOwner() public {
        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.transferWithWinternitz(nextPubkey, sig, payable(BOB), transferAmount);
    }
}
