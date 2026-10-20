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
        bytes32 commitment = keccak256("Specific Vault");
        (, , bytes memory payload) = _freshInitPayload("seed-specific-proxy");
        address expected = _computeWalletAddress(commitment, ALICE);

        vm.prank(ALICE);
        address walletAddr =
            factory.deploySpecificWalletProxy(commitment, 0, payable(ALICE), payload);

        assertEq(walletAddr, expected);
        _assertDeployedWalletState(walletAddr, commitment, ALICE);
    }

    function test_deploySpecificWalletProxy_deploysWithBalance() public {
        bytes32 commitment = keccak256("Specific Balance");
        (WOTSPlus.WinternitzAddress memory pubkey, , bytes memory payload) =
            _freshInitPayload("seed-specific");

        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy{
            value: INITIAL_DEPOSIT
        }(commitment, 0, payable(ALICE), payload);

        assertEq(walletAddr.balance, INITIAL_DEPOSIT);

        WOTSPlusImplementation wallet = WOTSPlusImplementation(
            payable(walletAddr)
        );
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, pubkey));
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
    }

    function test_deploySpecificWalletProxy_emitsWalletDeployedEvent() public {
        bytes32 commitment = keccak256("Vault ID 1");
        (, , bytes memory payload) = _freshInitPayload("seed1");

        vm.prank(ALICE);
        vm.recordLogs();
        factory.deploySpecificWalletProxy{value: INITIAL_DEPOSIT}(
            commitment,
            0,
            payable(ALICE),
            payload
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                keccak256(
                    "WalletDeployed(uint256,uint256,bytes32,address,address,address)"
                )
            ) {
                found = true;
                // Pins the emitted implementation to the impl at the requested index.
                (, , address implementation) = abi.decode(
                    logs[i].data,
                    (uint256, uint256, address)
                );
                assertEq(implementation, address(walletImplementation));
                break;
            }
        }
        assertTrue(found, "WalletDeployed event not emitted");
    }

    function test_deploySpecificWalletProxy_tracksCommitments() public {
        bytes32 commitmentA = keccak256("Specific Vault A");
        bytes32 commitmentB = keccak256("Specific Vault B");
        (, , bytes memory payloadA) = _freshInitPayload("seed-specific-a");
        (, , bytes memory payloadB) = _freshInitPayload("seed-specific-b");

        vm.startPrank(ALICE);
        factory.deploySpecificWalletProxy(commitmentA, 0, payable(ALICE), payloadA);
        factory.deploySpecificWalletProxy(commitmentB, 0, payable(ALICE), payloadB);
        vm.stopPrank();

        assertEq(factory.getCommitmentCount(ALICE), 2, "both specific deploys tracked");
        _assertCommitmentTracked(ALICE, commitmentA);
        _assertCommitmentTracked(ALICE, commitmentB);
    }

    function test_deploySpecificWalletProxy_deploysWithSpecificImpl() public {
        _vetSecondImpl();

        bytes32 commitment = keccak256("Specific Impl Index 1");
        (, , bytes memory payload) = _freshInitPayload("seed-specific-impl");

        // Deploy using the second implementation (index 1); the first stays active.
        vm.prank(ALICE);
        address walletAddr =
            factory.deploySpecificWalletProxy(commitment, 1, payable(ALICE), payload);

        _assertDeployedWalletState(walletAddr, commitment, ALICE);
    }

    function test_deploySpecificWalletProxy_deploysWithZeroValue() public {
        bytes32 commitment = keccak256("Zero Vault");
        (, , bytes memory payload) = _freshInitPayload("seed1");

        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy(
            commitment,
            0,
            payable(ALICE),
            payload
        );

        assertEq(walletAddr.balance, 0);
        assertTrue(walletAddr.code.length > 0);
    }

    // ── Additional coverage ─────────────────────────────────────────

    function test_deploySpecificWalletProxy_creationFeeStaysInFactory() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 commitment = keccak256("Fee Retention");
        (, , bytes memory payload) = _freshInitPayload("seed-fee");

        uint256 factoryBalBefore = address(factory).balance;
        uint256 deposit = INITIAL_DEPOSIT + CREATION_FEE;

        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy{value: deposit}(
            commitment,
            0,
            payable(ALICE),
            payload
        );

        assertEq(address(factory).balance, factoryBalBefore + CREATION_FEE);
        assertEq(walletAddr.balance, INITIAL_DEPOSIT);
    }

    function test_deploySpecificWalletProxy_exactCreationFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 commitment = keccak256("Exact Fee");
        (, , bytes memory payload) = _freshInitPayload("seed-exact");

        vm.prank(ALICE);
        address walletAddr = factory.deploySpecificWalletProxy{
            value: CREATION_FEE
        }(commitment, 0, payable(ALICE), payload);

        assertEq(walletAddr.balance, 0);
    }

    function test_deploySpecificWalletProxy_deployerIsNotOwner() public {
        bytes32 commitment = keccak256("Specific Deployed For BOB");
        (, , bytes memory payload) = _freshInitPayload("seed-specific-bob");

        vm.prank(ALICE);
        address walletAddr =
            factory.deploySpecificWalletProxy(commitment, 0, payable(BOB), payload);

        _assertDeployedWalletState(walletAddr, commitment, BOB);
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_deploySpecificWalletProxy_revertsWhen_indexOutOfBounds()
        public
    {
        bytes32 commitment = keccak256("OOB Vault");
        (, , bytes memory payload) = _freshInitPayload("seed1");

        vm.prank(ALICE);
        vm.expectRevert(EnumerableSetLib.IndexOutOfBounds.selector);
        factory.deploySpecificWalletProxy(
            commitment,
            999,
            payable(ALICE),
            payload
        );
    }

    function test_deploySpecificWalletProxy_revertsWhen_deprecated() public {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        bytes32 commitment = keccak256("Vault ID 1");
        (, , bytes memory payload) = _freshInitPayload("seed1");

        vm.prank(ALICE);
        vm.expectRevert(IWalletFactory.ImplementationDeprecated.selector);
        factory.deploySpecificWalletProxy(
            commitment,
            0,
            payable(ALICE),
            payload
        );
    }

    function test_deploySpecificWalletProxy_revertsWhen_insufficientCreationFee()
        public
    {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 commitment = keccak256("Underfunded Specific");
        (, , bytes memory payload) = _freshInitPayload("seed-under");

        uint256 sent = CREATION_FEE - 1;
        vm.prank(ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(
                IWalletFactory.InsufficientCreationFee.selector,
                sent,
                CREATION_FEE
            )
        );
        factory.deploySpecificWalletProxy{value: sent}(
            commitment,
            0,
            payable(ALICE),
            payload
        );
    }

    function test_deploySpecificWalletProxy_revertsWhen_duplicateCommitment()
        public
    {
        bytes32 commitment = keccak256("Duplicate Vault");
        (, , bytes memory payload1) = _freshInitPayload("seed1");

        vm.prank(ALICE);
        factory.deploySpecificWalletProxy(
            commitment,
            0,
            payable(ALICE),
            payload1
        );

        // Second deploy with same commitment should revert (CREATE3 collision)
        (, , bytes memory payload2) = _freshInitPayload("seed2");

        vm.prank(ALICE);
        vm.expectRevert(CREATE3.DeploymentFailed.selector);
        factory.deploySpecificWalletProxy(
            commitment,
            0,
            payable(ALICE),
            payload2
        );
    }

    function test_deploySpecificWalletProxy_revertsWhen_sameCommitmentDifferentSenders()
        public
    {
        bytes32 commitment = keccak256("Shared Vault");
        (, , bytes memory payload1) = _freshInitPayload("seed-alice");

        vm.prank(ALICE);
        factory.deploySpecificWalletProxy(
            commitment,
            0,
            payable(ALICE),
            payload1
        );

        // Bob tries same commitment — CREATE3 collision
        (, , bytes memory payload2) = _freshInitPayload("seed-bob");

        vm.prank(BOB);
        vm.expectRevert(CREATE3.DeploymentFailed.selector);
        factory.deploySpecificWalletProxy(
            commitment,
            0,
            payable(BOB),
            payload2
        );
    }

    function test_deploySpecificWalletProxy_revertsWhen_toIsZeroAddress()
        public
    {
        bytes32 commitment = keccak256("Specific Zero Owner");
        (, , bytes memory payload) = _freshInitPayload("specific-seed-zero");

        vm.prank(ALICE);
        vm.expectRevert(IWalletFactory.ZeroAddressOwner.selector);
        factory.deploySpecificWalletProxy(
            commitment,
            0,
            payable(address(0)),
            payload
        );
    }
}
