// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

import {IWOTSPlusImplementation} from "../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipFactory_deployLatestWalletProxy is QuipFactoryTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_deployLatestWalletProxy_deploysProxy() public {
        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        address expectedAddr = _computeWalletAddress(vaultId, ALICE);

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy(vaultId, payable(ALICE), payload);

        assertEq(walletAddr, expectedAddr);
        assertTrue(walletAddr.code.length > 0);

        // Check factory state
        assertEq(factory.wallets(vaultId), walletAddr);
        assertEq(factory.vaultIdOf(walletAddr), vaultId);
        assertNotEq(factory.getVaultIdIndex(ALICE, vaultId), type(uint256).max);

        // Check wallet state
        WOTSPlusImplementation wallet = WOTSPlusImplementation(payable(walletAddr));
        assertEq(wallet.owner(), ALICE);
        assertEq(address(wallet.quipFactory()), address(factory));
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    function test_deployLatestWalletProxy_deploysWithBalance() public {
        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(vaultId, payable(ALICE), payload);

        assertEq(walletAddr.balance, INITIAL_DEPOSIT);

        WOTSPlusImplementation wallet = WOTSPlusImplementation(payable(walletAddr));
        // The init payload here uses _encodeInitPayload which places `pubkey` at txn index 0.
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, pubkey));
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
    }

    function test_deployLatestWalletProxy_emitsQuipCreatedEvent() public {
        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        vm.recordLogs();
        factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(vaultId, payable(ALICE), payload);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == keccak256("QuipCreated(uint256,uint256,bytes32,address,address,address)")) {
                found = true;
                // Pins the emitted implementation to the latest active impl.
                (,, address implementation) = abi.decode(logs[i].data, (uint256, uint256, address));
                assertEq(implementation, address(walletImplementation));
                break;
            }
        }
        assertTrue(found, "QuipCreated event not emitted");
    }

    function test_deployLatestWalletProxy_tracksVaultIds() public {
        bytes32 vaultId1 = keccak256("Vault 1");
        bytes32 vaultId2 = keccak256("Vault 2");
        (WOTSPlus.WinternitzAddress memory pubkey1, bytes32 privateKey1) = _generateKeyPair("seed1");
        (WOTSPlus.WinternitzAddress memory pubkey2, bytes32 privateKey2) = _generateKeyPair("seed2");
        WOTSPlus.WinternitzAddress[] memory rKeys1 = _generateRecoveryKeys(privateKey1, 10);
        WOTSPlus.WinternitzAddress[] memory rKeys2 = _generateRecoveryKeys(privateKey2, 10);

        vm.startPrank(ALICE);
        factory.deployLatestWalletProxy(vaultId1, payable(ALICE), _encodeInitPayload(pubkey1, rKeys1));
        factory.deployLatestWalletProxy(vaultId2, payable(ALICE), _encodeInitPayload(pubkey2, rKeys2));
        vm.stopPrank();

        assertEq(factory.getVaultIdCount(ALICE), 2);
        assertNotEq(factory.getVaultIdIndex(ALICE, vaultId1), type(uint256).max);
        assertNotEq(factory.getVaultIdIndex(ALICE, vaultId2), type(uint256).max);
    }

    function test_deployLatestWalletProxy_usesLatestActiveImpl() public {
        // Deploy and vet a second implementation
        WOTSPlusImplementation impl2 = new WOTSPlusImplementation(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl2));

        // Deprecate the first
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy(vaultId, payable(ALICE), payload);

        assertTrue(walletAddr.code.length > 0);
        WOTSPlusImplementation wallet = WOTSPlusImplementation(payable(walletAddr));
        assertEq(wallet.owner(), ALICE);
    }

    function test_deployLatestWalletProxy_deploysWithZeroValue() public {
        bytes32 vaultId = keccak256("Zero Vault");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy(vaultId, payable(ALICE), payload);

        assertEq(walletAddr.balance, 0);
        assertTrue(walletAddr.code.length > 0);
    }

    // ── Additional coverage ─────────────────────────────────────────

    function test_deployLatestWalletProxy_creationFeeStaysInFactory() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Fee Retention");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-fee");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        uint256 factoryBalBefore = address(factory).balance;
        uint256 deposit = INITIAL_DEPOSIT + CREATION_FEE;

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy{value: deposit}(vaultId, payable(ALICE), payload);

        assertEq(address(factory).balance, factoryBalBefore + CREATION_FEE);
        assertEq(walletAddr.balance, INITIAL_DEPOSIT);
    }

    function test_deployLatestWalletProxy_exactCreationFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Exact Fee");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-exact");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy{value: CREATION_FEE}(vaultId, payable(ALICE), payload);

        assertEq(walletAddr.balance, 0);
    }

    function test_deployLatestWalletProxy_deployerIsNotOwner() public {
        bytes32 vaultId = keccak256("Deployed For BOB");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-for-bob");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy(vaultId, payable(BOB), payload);

        WOTSPlusImplementation w = WOTSPlusImplementation(payable(walletAddr));
        assertEq(w.owner(), BOB);
        assertEq(factory.wallets(vaultId), walletAddr);
        assertNotEq(factory.getVaultIdIndex(BOB, vaultId), type(uint256).max);
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_deployLatestWalletProxy_revertsWhen_noActiveImplementation() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        bytes32 vaultId = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IQuipFactory.NoActiveImplementation.selector);
        factory.deployLatestWalletProxy(vaultId, payable(ALICE), payload);
    }

    function test_deployLatestWalletProxy_revertsWhen_duplicateVaultId() public {
        bytes32 vaultId = keccak256("Duplicate Vault");
        (WOTSPlus.WinternitzAddress memory pubkey1, bytes32 pk1) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys1 = _generateRecoveryKeys(pk1, 10);
        bytes memory payload1 = _encodeInitPayload(pubkey1, rKeys1);

        vm.prank(ALICE);
        factory.deployLatestWalletProxy(vaultId, payable(ALICE), payload1);

        // Second deploy with same vaultId should revert (CREATE3 collision)
        (WOTSPlus.WinternitzAddress memory pubkey2, bytes32 pk2) = _generateKeyPair("seed2");
        WOTSPlus.WinternitzAddress[] memory rKeys2 = _generateRecoveryKeys(pk2, 10);
        bytes memory payload2 = _encodeInitPayload(pubkey2, rKeys2);

        vm.prank(ALICE);
        vm.expectRevert(CREATE3.DeploymentFailed.selector);
        factory.deployLatestWalletProxy(vaultId, payable(ALICE), payload2);
    }

    function test_deployLatestWalletProxy_revertsWhen_msgValueLessThanCreationFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Underfunded Vault");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        uint256 sent = CREATION_FEE - 1;
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(IQuipFactory.InsufficientCreationFee.selector, sent, CREATION_FEE));
        factory.deployLatestWalletProxy{value: sent}(vaultId, payable(ALICE), payload);
    }

    function test_deployLatestWalletProxy_revertsWhen_toIsZeroAddress() public {
        bytes32 vaultId = keccak256("Zero Owner");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-zero");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IQuipFactory.ZeroAddressOwner.selector);
        factory.deployLatestWalletProxy(vaultId, payable(address(0)), payload);
    }

    /// @dev vaultId == 0 is reserved as the "not deployed by this factory"
    ///      sentinel in the `vaultIdOf` reverse mapping; allowing it would
    ///      collapse the `OnlyWallet` gate on `updateWalletOwner`.
    function test_deployLatestWalletProxy_revertsWhen_vaultIdIsZero() public {
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 pk) = _generateKeyPair("seed-zero-vid");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(pk, 10);
        bytes memory payload = _encodeInitPayload(pubkey, rKeys);

        vm.prank(ALICE);
        vm.expectRevert(IQuipFactory.ZeroVaultId.selector);
        factory.deployLatestWalletProxy(bytes32(0), payable(ALICE), payload);
    }

    function test_deployLatestWalletProxy_revertsWhen_sameVaultIdDifferentSenders() public {
        bytes32 vaultId = keccak256("Shared Vault");
        (WOTSPlus.WinternitzAddress memory pubkey1, bytes32 pk1) = _generateKeyPair("seed-alice");
        WOTSPlus.WinternitzAddress[] memory rKeys1 = _generateRecoveryKeys(pk1, 10);
        bytes memory payload1 = _encodeInitPayload(pubkey1, rKeys1);

        vm.prank(ALICE);
        factory.deployLatestWalletProxy(vaultId, payable(ALICE), payload1);

        // Bob tries same vaultId — CREATE3 collision
        (WOTSPlus.WinternitzAddress memory pubkey2, bytes32 pk2) = _generateKeyPair("seed-bob");
        WOTSPlus.WinternitzAddress[] memory rKeys2 = _generateRecoveryKeys(pk2, 10);
        bytes memory payload2 = _encodeInitPayload(pubkey2, rKeys2);

        vm.prank(BOB);
        vm.expectRevert(CREATE3.DeploymentFailed.selector);
        factory.deployLatestWalletProxy(vaultId, payable(BOB), payload2);
    }
}
