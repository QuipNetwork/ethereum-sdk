// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol";
import {Vm} from "forge-std/Vm.sol";

contract QuipFactory_depositToWinternitz is QuipFactoryTest {
    function test_depositToWinternitz_deploysWallet() public {
        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey,) = _generateKeyPair("seed1");

        address expectedAddr = _computeWalletAddress(vaultId, ALICE);

        vm.prank(ALICE);
        address walletAddr = factory.depositToWinternitz(
            vaultId,
            payable(ALICE),
            pubkey
        );

        assertEq(walletAddr, expectedAddr);
        assertTrue(walletAddr.code.length > 0);

        // Check factory state
        assertEq(factory.quips(ALICE, vaultId), walletAddr);

        // Check wallet state
        QuipWallet wallet = QuipWallet(payable(walletAddr));
        assertEq(wallet.owner(), ALICE);
        assertEq(address(wallet.quipFactory()), address(factory));
    }

    function test_depositToWinternitz_deploysWalletWithBalance() public {
        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey,) = _generateKeyPair("seed1");

        vm.prank(ALICE);
        address walletAddr = factory.depositToWinternitz{value: INITIAL_DEPOSIT}(
            vaultId,
            payable(ALICE),
            pubkey
        );

        assertEq(walletAddr.balance, INITIAL_DEPOSIT);

        // Check wallet pqOwner
        QuipWallet wallet = QuipWallet(payable(walletAddr));
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, pubkey.publicSeed);
        assertEq(publicKeyHash, pubkey.publicKeyHash);
    }

    function test_depositToWinternitz_emitsQuipCreatedEvent() public {
        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey,) = _generateKeyPair("seed1");

        address expectedAddr = _computeWalletAddress(vaultId, ALICE);

        vm.prank(ALICE);
        vm.recordLogs();
        factory.depositToWinternitz{value: INITIAL_DEPOSIT}(
            vaultId,
            payable(ALICE),
            pubkey
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        // Find the QuipCreated event
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("QuipCreated(uint256,uint256,bytes32,address,(bytes32,bytes32),address)")) {
                found = true;
                break;
            }
        }
        assertTrue(found, "QuipCreated event not emitted");
    }

    function test_depositToWinternitz_tracksVaultIds() public {
        bytes32 vaultId1 = keccak256("Vault 1");
        bytes32 vaultId2 = keccak256("Vault 2");
        (WOTSPlus.WinternitzAddress memory pubkey1,) = _generateKeyPair("seed1");
        (WOTSPlus.WinternitzAddress memory pubkey2,) = _generateKeyPair("seed2");

        vm.startPrank(ALICE);
        factory.depositToWinternitz(vaultId1, payable(ALICE), pubkey1);
        factory.depositToWinternitz(vaultId2, payable(ALICE), pubkey2);
        vm.stopPrank();

        assertEq(factory.vaultIds(ALICE, 0), vaultId1);
        assertEq(factory.vaultIds(ALICE, 1), vaultId2);
    }
}
