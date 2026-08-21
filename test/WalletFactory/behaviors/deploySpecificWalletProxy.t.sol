// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

import {IWOTSPlusImplementation} from "../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract WalletFactory_deploySpecificWalletProxy is WalletFactoryTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_deploySpecificWalletProxy_deploysProxy() public {
        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        address expectedAddr = _computeWalletAddress(vaultId, ALICE);

        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 0, payable(ALICE), payload);

        assertEq(walletAddr, expectedAddr);
        assertTrue(walletAddr.code.length > 0);

        // Check factory state
        assertEq(factory.wallets(_salt(vaultId)), walletAddr);
        assertEq(factory.vaultIdOf(walletAddr), vaultId);
        assertNotEq(factory.getVaultIdIndex(ALICE, _salt(vaultId)), type(uint256).max);

        // Check wallet state
        WOTSPlusImplementation wallet = WOTSPlusImplementation(payable(walletAddr));
        assertEq(wallet.owner(), ALICE);
        assertEq(address(wallet.quipFactory()), address(factory));
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_deploySpecificWalletProxy_deploysWithBalance() public {
        bytes32 vaultId = keccak256("Specific Balance");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-specific");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        address walletAddr =
            factory.deploySpecificWalletProxy{value: INITIAL_DEPOSIT}(vaultId, COMMITMENT, 0, payable(ALICE), payload);

        assertEq(walletAddr.balance, INITIAL_DEPOSIT);

        WOTSPlusImplementation wallet = WOTSPlusImplementation(payable(walletAddr));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, pubkey));
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
    }

    function test_deploySpecificWalletProxy_emitsWalletDeployedEvent() public {
        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        vm.recordLogs();
        factory.deploySpecificWalletProxy{value: INITIAL_DEPOSIT}(vaultId, COMMITMENT, 0, payable(ALICE), payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("WalletDeployed(uint256,uint256,bytes32,address,address,address)")) {
                found = true;
                // Pins the emitted implementation to the impl at the requested index.
                (,, address implementation) = abi.decode(logs[i].data, (uint256, uint256, address));
                assertEq(implementation, address(walletImplementation));
                break;
            }
        }
        assertTrue(found, "WalletDeployed event not emitted");
    }

    function test_deploySpecificWalletProxy_tracksVaultIds() public {
        bytes32 vaultId1 = keccak256("Vault 1");
        bytes32 vaultId2 = keccak256("Vault 2");
        (WOTSPlus.WinternitzAddress memory pubkey1, bytes32 privateKey1) = _generateKeyPair("seed1");
        (WOTSPlus.WinternitzAddress memory pubkey2, bytes32 privateKey2) = _generateKeyPair("seed2");
        WOTSPlus.WinternitzAddress[] memory rKeys1 = _generateRecoveryKeys(privateKey1, 10);
        WOTSPlus.WinternitzAddress[] memory rKeys2 = _generateRecoveryKeys(privateKey2, 10);

        vm.startPrank(ALICE);
        factory.deploySpecificWalletProxy(vaultId1, COMMITMENT, 0, payable(ALICE), _encodeInitPayload(pubkey1, rKeys1));
        factory.deploySpecificWalletProxy(vaultId2, COMMITMENT, 0, payable(ALICE), _encodeInitPayload(pubkey2, rKeys2));
        vm.stopPrank();

        assertEq(factory.getVaultIdCount(ALICE), 2);
        assertNotEq(factory.getVaultIdIndex(ALICE, _salt(vaultId1)), type(uint256).max);
        assertNotEq(factory.getVaultIdIndex(ALICE, _salt(vaultId2)), type(uint256).max);
    }

    function test_deploySpecificWalletProxy_deploysWithSpecificImpl() public {
        // Deploy and vet a second implementation
        WOTSPlusImplementation impl2 = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl2));

        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        // Deploy using the second implementation (index 1)
        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 1, payable(ALICE), payload);

        assertTrue(walletAddr.code.length > 0);
        WOTSPlusImplementation wallet = WOTSPlusImplementation(payable(walletAddr));
        assertEq(wallet.owner(), ALICE);
    }

    function test_deploySpecificWalletProxy_deploysWithZeroValue() public {
        bytes32 vaultId = keccak256("Zero Vault");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 0, payable(ALICE), payload);

        assertEq(walletAddr.balance, 0);
        assertTrue(walletAddr.code.length > 0);
    }

    // ── Additional coverage ─────────────────────────────────────────

    function test_deploySpecificWalletProxy_creationFeeStaysInFactory() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Fee Retention");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-fee");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        uint256 factoryBalBefore = address(factory).balance;
        uint256 deposit = INITIAL_DEPOSIT + CREATION_FEE;

        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy{value: deposit}(vaultId, COMMITMENT, 0, payable(ALICE), payload);

        assertEq(address(factory).balance, factoryBalBefore + CREATION_FEE);
        assertEq(walletAddr.balance, INITIAL_DEPOSIT);
    }

    function test_deploySpecificWalletProxy_exactCreationFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Exact Fee");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-exact");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy{value: CREATION_FEE}(vaultId, COMMITMENT, 0, payable(ALICE), payload);

        assertEq(walletAddr.balance, 0);
    }

    function test_deploySpecificWalletProxy_deployerIsNotOwner() public {
        bytes32 vaultId = keccak256("Deployed For BOB");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-for-bob");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 0, payable(BOB), payload);

        WOTSPlusImplementation w = WOTSPlusImplementation(payable(walletAddr));
        assertEq(w.owner(), BOB);
        assertEq(factory.wallets(_salt(vaultId)), walletAddr);
        assertNotEq(factory.getVaultIdIndex(BOB, _salt(vaultId)), type(uint256).max);
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_deploySpecificWalletProxy_revertsWhen_indexOutOfBounds() public {
        bytes32 vaultId = keccak256("OOB Vault");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(EnumerableSetLib.IndexOutOfBounds.selector);
        factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 999, payable(ALICE), payload);
    }

    function test_deploySpecificWalletProxy_revertsWhen_deprecated() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IWalletFactory.ImplementationDeprecated.selector);
        factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 0, payable(ALICE), payload);
    }

    function test_deploySpecificWalletProxy_revertsWhen_insufficientCreationFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Underfunded Specific");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-under");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        uint256 sent = CREATION_FEE - 1;
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(IWalletFactory.InsufficientCreationFee.selector, sent, CREATION_FEE));
        factory.deploySpecificWalletProxy{value: sent}(vaultId, COMMITMENT, 0, payable(ALICE), payload);
    }

    function test_deploySpecificWalletProxy_revertsWhen_duplicateVaultId() public {
        bytes32 vaultId = keccak256("Duplicate Vault");
        (WOTSPlus.WinternitzAddress memory pubkey1, bytes32 pk1) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys1 = _generateRecoveryKeys(pk1, 10);
        bytes memory payload1 = _encodeInitPayload(pubkey1, rKeys1);

        vm.prank(ALICE);
        factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 0, payable(ALICE), payload1);

        // Second deploy with same vaultId should revert (CREATE3 collision)
        (WOTSPlus.WinternitzAddress memory pubkey2, bytes32 pk2) = _generateKeyPair("seed2");
        WOTSPlus.WinternitzAddress[] memory rKeys2 = _generateRecoveryKeys(pk2, 10);
        bytes memory payload2 = _encodeInitPayload(pubkey2, rKeys2);

        vm.prank(ALICE);
        vm.expectRevert(CREATE3.DeploymentFailed.selector);
        factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 0, payable(ALICE), payload2);
    }

    function test_deploySpecificWalletProxy_revertsWhen_sameVaultIdDifferentSenders() public {
        bytes32 vaultId = keccak256("Shared Vault");
        (WOTSPlus.WinternitzAddress memory pubkey1, bytes32 pk1) = _generateKeyPair("seed-alice");
        WOTSPlus.WinternitzAddress[] memory rKeys1 = _generateRecoveryKeys(pk1, 10);
        bytes memory payload1 = _encodeInitPayload(pubkey1, rKeys1);

        vm.prank(ALICE);
        factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 0, payable(ALICE), payload1);

        // Bob tries same vaultId — CREATE3 collision
        (WOTSPlus.WinternitzAddress memory pubkey2, bytes32 pk2) = _generateKeyPair("seed-bob");
        WOTSPlus.WinternitzAddress[] memory rKeys2 = _generateRecoveryKeys(pk2, 10);
        bytes memory payload2 = _encodeInitPayload(pubkey2, rKeys2);

        vm.prank(BOB);
        vm.expectRevert(CREATE3.DeploymentFailed.selector);
        factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 0, payable(BOB), payload2);
    }

    function test_deploySpecificWalletProxy_revertsWhen_toIsZeroAddress() public {
        bytes32 vaultId = keccak256("Specific Zero Owner");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("specific-seed-zero");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IWalletFactory.ZeroAddressOwner.selector);
        factory.deploySpecificWalletProxy(vaultId, COMMITMENT, 0, payable(address(0)), payload);
    }
}
