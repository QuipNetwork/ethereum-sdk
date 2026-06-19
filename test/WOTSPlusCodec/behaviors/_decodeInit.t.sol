// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeInit is WOTSPlusCodecTest {
    function test_exposed_decodeInit_decodesCorrectly() public view {
        bytes memory payload = _buildInitPayload(42);
        (
            WOTSPlus.WinternitzAddress memory disasterKey,
            WOTSPlus.WinternitzAddress memory ownershipKey,
            WOTSPlus.WinternitzAddress[10] memory txnKeys,
            WOTSPlus.WinternitzAddress[10] memory recKeys,
            WOTSPlus.WinternitzAddress[10] memory verKeys
        ) = codec.exposed_decodeInit(payload);

        assertEq(disasterKey.publicSeed, bytes32(uint256(42 + 500)));
        assertEq(disasterKey.publicKeyHash, bytes32(uint256(42 + 501)));
        assertEq(ownershipKey.publicSeed, bytes32(uint256(42 + 600)));
        assertEq(ownershipKey.publicKeyHash, bytes32(uint256(42 + 601)));
        for (uint256 i = 0; i < 10; i++) {
            assertEq(txnKeys[i].publicSeed, bytes32(uint256(42 + i * 2)));
            assertEq(txnKeys[i].publicKeyHash, bytes32(uint256(42 + 1 + i * 2)));
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(recKeys[i].publicSeed, bytes32(uint256(42 + 100 + i * 2)));
            assertEq(recKeys[i].publicKeyHash, bytes32(uint256(42 + 101 + i * 2)));
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(verKeys[i].publicSeed, bytes32(uint256(42 + 200 + i * 2)));
            assertEq(verKeys[i].publicKeyHash, bytes32(uint256(42 + 201 + i * 2)));
        }
    }

    function test_exposed_decodeInit_revertsWhen_extraBytes() public {
        bytes memory payload = _buildInitPayload(42);
        payload = abi.encodePacked(payload, bytes32(uint256(0xFF)), bytes32(uint256(0xFF)), bytes32(uint256(0xFF)));
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 2048, 2144));
        codec.exposed_decodeInit(payload);
    }

    function test_exposed_decodeInit_handlesMaxValues() public view {
        bytes memory payload = new bytes(0);
        // disaster (2) + ownership (2) + txn (20) + rec (20) + ver (20) = 64 bytes32 slots.
        for (uint256 i = 0; i < 64; i++) {
            payload = abi.encodePacked(payload, bytes32(type(uint256).max));
        }
        (,, WOTSPlus.WinternitzAddress[10] memory txnKeys,,) = codec.exposed_decodeInit(payload);
        assertEq(txnKeys[0].publicSeed, bytes32(type(uint256).max));
        assertEq(txnKeys[0].publicKeyHash, bytes32(type(uint256).max));
    }

    function test_exposed_decodeInit_revertsWhen_emptyPayload() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 2048, 0));
        codec.exposed_decodeInit("");
    }

    function test_exposed_decodeInit_revertsWhen_truncatedPayload() public {
        bytes memory payload = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 2048, 64));
        codec.exposed_decodeInit(payload);
    }

    /// @dev Property: any payload length other than 2048 reverts with
    ///      MalformedPayload(2048, length). Fuzz across the full range to
    ///      exhaust off-by-N drift in the length precondition.
    function testFuzz_exposed_decodeInit_revertsWhen_wrongLength(uint256 len) public {
        len = bound(len, 0, 4000);
        vm.assume(len != 2048);
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 2048, len));
        codec.exposed_decodeInit(_filledBytes(len));
    }
}
