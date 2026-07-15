// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Test.sol";
import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactoryHarness} from "../../harness/WalletFactoryHarness.sol";
import {WOTSPlusImplementation} from "../../../contracts/deprecated/wots/WOTSPlusImplementation.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {IWOTSPlusImplementation} from "../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

contract WalletFactory__deployProxy is WalletFactoryTest {
    WalletFactoryHarness public harness;
    WOTSPlusImplementation public impl;

    function setUp() public override {
        super.setUp();
        WalletFactoryHarness harnessImpl = new WalletFactoryHarness(0.1 ether);
        harness = WalletFactoryHarness(payable(LibClone.deployERC1967(address(harnessImpl))));
        harness.initialize(payable(ADMIN));
        impl = new WOTSPlusImplementation(payable(address(harness)));
        vm.prank(ADMIN);
        harness.vetImplementation(address(impl));
    }

    function _buildPayload() internal pure returns (bytes memory) {
        // disaster recovery key (64 bytes): seed 500, hash 501.
        bytes memory payload = abi.encodePacked(bytes32(uint256(500)), bytes32(uint256(501)));
        // ownership key (64 bytes): seed 600, hash 601.
        payload = abi.encodePacked(payload, bytes32(uint256(600)), bytes32(uint256(601)));
        // 10 transaction keys (640 bytes): seeds 1,3,5,...,19 / hashes 2,4,6,...,20.
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, bytes32(uint256(2 * i + 1)), bytes32(uint256(2 * i + 2)));
        }
        // 10 recovery keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, bytes32(i + 100), bytes32(i + 200));
        }
        // 10 verification keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, bytes32(i + 300), bytes32(i + 400));
        }
        return payload;
    }

    function test_exposed_deployProxy_deploysAndInitializes() public {
        bytes memory payload = _buildPayload();
        address proxy =
            harness.exposed_deployProxy{value: 1 ether}(address(impl), keccak256("v1"), payable(ALICE), payload);
        assertEq(WOTSPlusImplementation(payable(proxy)).owner(), ALICE);
    }

    function test_exposed_deployProxy_storesQuipMapping() public {
        bytes32 vaultId = keccak256("v2");
        bytes memory payload = _buildPayload();
        address proxy = harness.exposed_deployProxy{value: 1 ether}(address(impl), vaultId, payable(ALICE), payload);
        assertEq(harness.wallets(vaultId), proxy);
        assertEq(harness.vaultIdOf(proxy), vaultId);
    }

    function test_exposed_deployProxy_pushesVaultId() public {
        bytes32 vaultId = keccak256("v3");
        bytes memory payload = _buildPayload();
        harness.exposed_deployProxy{value: 1 ether}(address(impl), vaultId, payable(ALICE), payload);
        assertEq(harness.getVaultIdCount(ALICE), 1);
        assertNotEq(harness.getVaultIdIndex(ALICE, vaultId), type(uint256).max);
    }

    function test_exposed_deployProxy_emitsWalletDeployed() public {
        bytes memory payload = _buildPayload();
        bytes32 vaultId = keccak256("v-event");

        vm.recordLogs();
        address proxy = harness.exposed_deployProxy{value: 1 ether}(address(impl), vaultId, payable(ALICE), payload);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter == address(harness) && logs[i].topics[0] == IWalletFactory.WalletDeployed.selector) {
                found = true;
                // vaultId / creator / quip are indexed → topics[1..3].
                bytes32 vid = logs[i].topics[1];
                address creator = address(uint160(uint256(logs[i].topics[2])));
                address quip = address(uint160(uint256(logs[i].topics[3])));
                (uint256 amount,, address implementation) =
                    abi.decode(logs[i].data, (uint256, uint256, address));
                assertEq(amount, 1 ether);
                assertEq(vid, vaultId);
                assertEq(creator, ALICE);
                // The event carries the implementation the proxy was deployed
                // with; the init payload itself is opaque to the factory.
                assertEq(implementation, address(impl));
                assertEq(quip, proxy);
                break;
            }
        }
        assertTrue(found);
    }

    function test_exposed_deployProxy_deductsCreationFee() public {
        vm.prank(ADMIN);
        harness.setCreationFee(0.01 ether);

        bytes memory payload = _buildPayload();
        address proxy =
            harness.exposed_deployProxy{value: 1 ether}(address(impl), keccak256("v4"), payable(ALICE), payload);
        // 1 ether - 0.01 fee = 0.99 ether forwarded to proxy
        assertEq(proxy.balance, 0.99 ether);
    }

    function test_exposed_deployProxy_revertsWhen_zeroAddressOwner() public {
        bytes memory payload = _buildPayload();
        vm.expectRevert(IWOTSPlusImplementation.ZeroAddressOwner.selector);
        harness.exposed_deployProxy{value: 1 ether}(address(impl), keccak256("v5"), payable(address(0)), payload);
    }

    function test_exposed_deployProxy_revertsWhen_insufficientFee() public {
        vm.prank(ADMIN);
        harness.setCreationFee(0.01 ether);

        bytes memory payload = _buildPayload();
        vm.expectRevert(abi.encodeWithSelector(IWalletFactory.InsufficientCreationFee.selector, 0.005 ether, 0.01 ether));
        harness.exposed_deployProxy{value: 0.005 ether}(address(impl), keccak256("v6"), payable(ALICE), payload);
    }
}
