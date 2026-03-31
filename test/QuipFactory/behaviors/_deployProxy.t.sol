// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test, Vm} from "forge-std-1.14.0/Test.sol";
import {QuipFactoryHarness} from "../../harness/QuipFactoryHarness.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipFactory___deployProxy is Test {
    QuipFactoryHarness public factory;
    QuipWallet public impl;
    address public ADMIN = makeAddr("admin");
    address public ALICE = makeAddr("alice");

    function setUp() public {
        vm.deal(ADMIN, 10 ether);
        vm.deal(ALICE, 10 ether);
        factory = new QuipFactoryHarness(payable(ADMIN), 0.1 ether);
        impl = new QuipWallet(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(impl));
    }

    function _buildPayload() internal pure returns (bytes memory) {
        bytes memory payload;
        // pqOwner (64 bytes)
        payload = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)));
        // 10 recovery keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, bytes32(i + 100), bytes32(i + 200));
        }
        return payload;
    }

    function test_exposed_deployProxy_deploysAndInitializes() public {
        bytes memory payload = _buildPayload();
        address proxy = factory.exposed_deployProxy{value: 1 ether}(
            address(impl), keccak256("v1"), payable(ALICE), payload
        );
        assertEq(QuipWallet(payable(proxy)).owner(), ALICE);
    }

    function test_exposed_deployProxy_storesQuipMapping() public {
        bytes32 vaultId = keccak256("v2");
        bytes memory payload = _buildPayload();
        address proxy = factory.exposed_deployProxy{value: 1 ether}(
            address(impl), vaultId, payable(ALICE), payload
        );
        assertEq(factory.quips(ALICE, vaultId), proxy);
    }

    function test_exposed_deployProxy_pushesVaultId() public {
        bytes32 vaultId = keccak256("v3");
        bytes memory payload = _buildPayload();
        factory.exposed_deployProxy{value: 1 ether}(
            address(impl), vaultId, payable(ALICE), payload
        );
        assertEq(factory.vaultIds(ALICE, 0), vaultId);
    }

    function test_exposed_deployProxy_emitsQuipCreated() public {
        bytes memory payload = _buildPayload();
        bytes32 vaultId = keccak256("v-event");

        vm.recordLogs();
        address proxy = factory.exposed_deployProxy{value: 1 ether}(
            address(impl), vaultId, payable(ALICE), payload
        );
        Vm.Log[] memory logs = vm.getRecordedLogs();

        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter == address(factory) && logs[i].topics[0] == IQuipFactory.QuipCreated.selector) {
                found = true;
                (
                    uint256 amount,,
                    bytes32 vid,
                    address creator,
                    WOTSPlus.WinternitzAddress memory pqPub,
                    address quip
                ) = abi.decode(logs[i].data, (uint256, uint256, bytes32, address, WOTSPlus.WinternitzAddress, address));
                assertEq(amount, 1 ether);
                assertEq(vid, vaultId);
                assertEq(creator, ALICE);
                assertEq(pqPub.publicSeed, bytes32(uint256(1)));
                assertEq(pqPub.publicKeyHash, bytes32(uint256(2)));
                assertEq(quip, proxy);
                break;
            }
        }
        assertTrue(found);
    }

    function test_exposed_deployProxy_deductsCreationFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(0.01 ether);

        bytes memory payload = _buildPayload();
        address proxy = factory.exposed_deployProxy{value: 1 ether}(
            address(impl), keccak256("v4"), payable(ALICE), payload
        );
        // 1 ether - 0.01 fee = 0.99 ether forwarded to proxy
        assertEq(proxy.balance, 0.99 ether);
    }

    function test_exposed_deployProxy_revertsWhen_zeroAddressOwner() public {
        bytes memory payload = _buildPayload();
        vm.expectRevert(IQuipWallet.ZeroAddressOwner.selector);
        factory.exposed_deployProxy{value: 1 ether}(
            address(impl), keccak256("v5"), payable(address(0)), payload
        );
    }

    function test_exposed_deployProxy_revertsWhen_insufficientFee() public {
        vm.prank(ADMIN);
        factory.setCreationFee(0.01 ether);

        bytes memory payload = _buildPayload();
        vm.expectRevert(
            abi.encodeWithSelector(IQuipFactory.InsufficientCreationFee.selector, 0.005 ether, 0.01 ether)
        );
        factory.exposed_deployProxy{value: 0.005 ether}(
            address(impl), keccak256("v6"), payable(ALICE), payload
        );
    }
}
