// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

contract QuipWallet_initialize is QuipWalletTest {
    function test_initialize_setsOwner() public view {
        assertEq(wallet.owner(), ALICE);
    }

    function test_initialize_setsPqOwner() public view {
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
    }

    function test_initialize_setsRecoveryKeys() public view {
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        for (uint256 i = 0; i < recoveryPubkeys.length; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
        }
    }

    function test_initialize_setsQuipFactory() public view {
        assertEq(address(wallet.quipFactory()), address(factory));
    }

    function test_initialize_emitsWalletInitialized() public {
        QuipWallet freshWallet = _deployFreshProxy("fresh-event");
        (
            WOTSPlus.WinternitzAddress memory newPubkey,
            bytes32 newPrivKey
        ) = _generateKeyPair("event-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            newPrivKey,
            10
        );
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(address(factory));
        vm.recordLogs();
        freshWallet.initialize(payable(ALICE), payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.WalletInitialized.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "WalletInitialized event not emitted");
    }

    function test_initialize_revertsWhen_ownerIsZero() public {
        QuipWallet freshWallet = _deployFreshProxy("fresh-zero-owner");
        (
            WOTSPlus.WinternitzAddress memory newPubkey,
            bytes32 newPrivKey
        ) = _generateKeyPair("new-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            newPrivKey,
            10
        );
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(IQuipWallet.ZeroAddressOwner.selector);
        freshWallet.initialize(payable(address(0)), payload);
    }

    function test_initialize_revertsWhen_recoveryKeyHashIsZero() public {
        QuipWallet freshWallet = _deployFreshProxy("fresh-zero-recovery-hash");
        (
            WOTSPlus.WinternitzAddress memory newPubkey,
            bytes32 newPrivKey
        ) = _generateKeyPair("new-seed");

        WOTSPlus.WinternitzAddress[] memory badRecovery = _generateRecoveryKeys(
            newPrivKey,
            10
        );
        badRecovery[5] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        bytes memory payload = _encodeInitPayload(newPubkey, badRecovery);

        vm.prank(address(factory));
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_alreadyInitialized() public {
        (
            WOTSPlus.WinternitzAddress memory newPubkey,
            bytes32 newPrivKey
        ) = _generateKeyPair("new-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            newPrivKey,
            10
        );
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        wallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_callerNotFactory() public {
        QuipWallet freshWallet = _deployFreshProxy("fresh-not-factory");
        (
            WOTSPlus.WinternitzAddress memory newPubkey,
            bytes32 newPrivKey
        ) = _generateKeyPair("new-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            newPrivKey,
            10
        );
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidFactory.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_publicSeedEmpty() public {
        QuipWallet freshWallet = _deployFreshProxy("fresh-empty-seed");
        WOTSPlus.WinternitzAddress memory emptyPubkey = WOTSPlus
            .WinternitzAddress({
                publicSeed: bytes32(0),
                publicKeyHash: bytes32("non-empty")
            });
        (, bytes32 privKey) = _generateKeyPair("dummy");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            privKey,
            10
        );
        bytes memory payload = _encodeInitPayload(emptyPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_publicKeyHashEmpty() public {
        QuipWallet freshWallet = _deployFreshProxy("fresh-empty-hash");
        WOTSPlus.WinternitzAddress memory emptyPubkey = WOTSPlus
            .WinternitzAddress({
                publicSeed: bytes32("non-empty"),
                publicKeyHash: bytes32(0)
            });
        (, bytes32 privKey) = _generateKeyPair("dummy");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            privKey,
            10
        );
        bytes memory payload = _encodeInitPayload(emptyPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_recoveryKeyHasZeroSeed() public {
        QuipWallet freshWallet = _deployFreshProxy("fresh-zero-recovery");
        (
            WOTSPlus.WinternitzAddress memory newPubkey,
            bytes32 newPrivKey
        ) = _generateKeyPair("new-seed");

        WOTSPlus.WinternitzAddress[] memory badRecovery = _generateRecoveryKeys(
            newPrivKey,
            10
        );
        badRecovery[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        bytes memory payload = _encodeInitPayload(newPubkey, badRecovery);

        vm.prank(address(factory));
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }

    function test_initialize_revertsWhen_duplicateRecoveryKey() public {
        QuipWallet freshWallet = _deployFreshProxy("fresh-dup-recovery");
        (
            WOTSPlus.WinternitzAddress memory newPubkey,
            bytes32 newPrivKey
        ) = _generateKeyPair("dup-seed");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            newPrivKey,
            10
        );
        rKeys[5] = rKeys[0]; // duplicate!
        bytes memory payload = _encodeInitPayload(newPubkey, rKeys);

        vm.prank(address(factory));
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        freshWallet.initialize(payable(ALICE), payload);
    }
}
