// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

import {IWOTSPlusImplementation} from "../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract WalletFactory_deployLatestWalletProxy is WalletFactoryTest {
    // ── Happy paths ──────────────────────────────────────────────────

    function test_deployLatestWalletProxy_deploysProxy() public {
        bytes32 commitment = keccak256("Latest Vault");
        (, , bytes memory payload) = _freshInitPayload("seed-latest");
        address expectedAddr = _computeWalletAddress(commitment, ALICE);

        vm.prank(ALICE);
        address walletAddr =
            factory.deployLatestWalletProxy(commitment, payable(ALICE), payload);

        assertEq(walletAddr, expectedAddr);
        _assertDeployedWalletState(walletAddr, commitment, ALICE);
    }

    function test_deployLatestWalletProxy_deploysWithBalance() public {
        bytes32 commitment = keccak256("Vault ID 1");
        (WOTSPlus.WinternitzAddress memory pubkey, , bytes memory payload) =
            _freshInitPayload("seed1");

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy{
            value: INITIAL_DEPOSIT
        }(commitment, payable(ALICE), payload);

        assertEq(walletAddr.balance, INITIAL_DEPOSIT);

        WOTSPlusImplementation wallet = WOTSPlusImplementation(
            payable(walletAddr)
        );
        // The init payload here uses _encodeInitPayload which places `pubkey` at txn index 0.
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, pubkey));
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
    }

    function test_deployLatestWalletProxy_emitsWalletDeployedEvent() public {
        bytes32 commitment = keccak256("Vault ID 1");
        (, , bytes memory payload) = _freshInitPayload("seed1");

        vm.prank(ALICE);
        vm.recordLogs();
        factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(
            commitment,
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
                // Pins the emitted implementation to the latest active impl.
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

    function test_deployLatestWalletProxy_tracksCommitments() public {
        bytes32 commitment1 = keccak256("Latest Vault 1");
        bytes32 commitment2 = keccak256("Latest Vault 2");
        (, , bytes memory payload1) = _freshInitPayload("seed-latest-1");
        (, , bytes memory payload2) = _freshInitPayload("seed-latest-2");

        vm.startPrank(ALICE);
        factory.deployLatestWalletProxy(commitment1, payable(ALICE), payload1);
        factory.deployLatestWalletProxy(commitment2, payable(ALICE), payload2);
        vm.stopPrank();

        assertEq(factory.getCommitmentCount(ALICE), 2);
        _assertCommitmentTracked(ALICE, commitment1);
        _assertCommitmentTracked(ALICE, commitment2);
    }

    function test_deployLatestWalletProxy_usesLatestActiveImpl() public {
        _vetSecondImpl();
        // Deprecate the first: the latest ACTIVE implementation is now impl2.
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        bytes32 commitment = keccak256("Latest After Deprecate");
        (, , bytes memory payload) = _freshInitPayload("seed-latest-active");

        vm.prank(ALICE);
        address walletAddr =
            factory.deployLatestWalletProxy(commitment, payable(ALICE), payload);

        _assertDeployedWalletState(walletAddr, commitment, ALICE);
    }

    function test_deployLatestWalletProxy_deploysWithZeroValue() public {
        bytes32 commitment = keccak256("Zero Vault");
        (, , bytes memory payload) = _freshInitPayload("seed1");

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy(
            commitment,
            payable(ALICE),
            payload
        );

        assertEq(walletAddr.balance, 0);
        assertTrue(walletAddr.code.length > 0);
    }

    // ── Additional coverage ─────────────────────────────────────────

    function test_deployLatestWalletProxy_creationFeeStaysInFactory() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 commitment = keccak256("Fee Retention");
        (, , bytes memory payload) = _freshInitPayload("seed-fee");

        uint256 factoryBalBefore = address(factory).balance;
        uint256 deposit = INITIAL_DEPOSIT + CREATION_FEE;

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy{value: deposit}(
            commitment,
            payable(ALICE),
            payload
        );

        assertEq(address(factory).balance, factoryBalBefore + CREATION_FEE);
        assertEq(walletAddr.balance, INITIAL_DEPOSIT);
    }

    function test_deployLatestWalletProxy_exactCreationFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 commitment = keccak256("Exact Fee");
        (, , bytes memory payload) = _freshInitPayload("seed-exact");

        vm.prank(ALICE);
        address walletAddr = factory.deployLatestWalletProxy{
            value: CREATION_FEE
        }(commitment, payable(ALICE), payload);

        assertEq(walletAddr.balance, 0);
    }

    function test_deployLatestWalletProxy_deployerIsNotOwner() public {
        bytes32 commitment = keccak256("Latest Deployed For BOB");
        (, , bytes memory payload) = _freshInitPayload("seed-for-bob");

        vm.prank(ALICE);
        address walletAddr =
            factory.deployLatestWalletProxy(commitment, payable(BOB), payload);

        _assertDeployedWalletState(walletAddr, commitment, BOB);
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_deployLatestWalletProxy_revertsWhen_noActiveImplementation()
        public
    {
        vm.prank(ADMIN);
        factory.deprecateImplementation(address(walletImplementation));

        bytes32 commitment = keccak256("Vault ID 1");
        (, , bytes memory payload) = _freshInitPayload("seed1");

        vm.prank(ALICE);
        vm.expectRevert(IWalletFactory.NoActiveImplementation.selector);
        factory.deployLatestWalletProxy(commitment, payable(ALICE), payload);
    }

    function test_deployLatestWalletProxy_revertsWhen_duplicateCommitment()
        public
    {
        bytes32 commitment = keccak256("Duplicate Vault");
        (, , bytes memory payload1) = _freshInitPayload("seed1");

        vm.prank(ALICE);
        factory.deployLatestWalletProxy(commitment, payable(ALICE), payload1);

        // Second deploy with same commitment should revert (CREATE3 collision)
        (, , bytes memory payload2) = _freshInitPayload("seed2");

        vm.prank(ALICE);
        vm.expectRevert(CREATE3.DeploymentFailed.selector);
        factory.deployLatestWalletProxy(commitment, payable(ALICE), payload2);
    }

    function test_deployLatestWalletProxy_revertsWhen_msgValueLessThanCreationFee()
        public
    {
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 commitment = keccak256("Underfunded Vault");
        (, , bytes memory payload) = _freshInitPayload("seed1");

        uint256 sent = CREATION_FEE - 1;
        vm.prank(ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(
                IWalletFactory.InsufficientCreationFee.selector,
                sent,
                CREATION_FEE
            )
        );
        factory.deployLatestWalletProxy{value: sent}(
            commitment,
            payable(ALICE),
            payload
        );
    }

    function test_deployLatestWalletProxy_revertsWhen_toIsZeroAddress() public {
        bytes32 commitment = keccak256("Zero Owner");
        (, , bytes memory payload) = _freshInitPayload("seed-zero");

        vm.prank(ALICE);
        vm.expectRevert(IWalletFactory.ZeroAddressOwner.selector);
        factory.deployLatestWalletProxy(
            commitment,
            payable(address(0)),
            payload
        );
    }

    /// @dev commitment == 0 is reserved as the "not deployed by this factory"
    ///      sentinel in the `commitmentOf` reverse mapping; allowing it would
    ///      collapse the `OnlyWallet` gate on `updateWalletOwner`.
    function test_deployLatestWalletProxy_revertsWhen_commitmentIsZero()
        public
    {
        (, , bytes memory payload) = _freshInitPayload("seed-zero-vid");

        vm.prank(ALICE);
        vm.expectRevert(IWalletFactory.ZeroCommitment.selector);
        factory.deployLatestWalletProxy(bytes32(0), payable(ALICE), payload);
    }

    function test_deployLatestWalletProxy_revertsWhen_sameCommitmentDifferentSenders()
        public
    {
        bytes32 commitment = keccak256("Shared Vault");
        (, , bytes memory payload1) = _freshInitPayload("seed-alice");

        vm.prank(ALICE);
        factory.deployLatestWalletProxy(commitment, payable(ALICE), payload1);

        // Bob tries same commitment — CREATE3 collision
        (, , bytes memory payload2) = _freshInitPayload("seed-bob");

        vm.prank(BOB);
        vm.expectRevert(CREATE3.DeploymentFailed.selector);
        factory.deployLatestWalletProxy(commitment, payable(BOB), payload2);
    }
}
