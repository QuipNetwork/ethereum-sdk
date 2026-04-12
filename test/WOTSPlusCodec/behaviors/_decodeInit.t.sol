// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeInit is WOTSPlusCodecTest {
    function test_exposed_decodeInit_decodesCorrectly() public view {
        bytes memory payload = _buildInitPayload(42);
        (WOTSPlus.WinternitzAddress memory pq, WOTSPlus.WinternitzAddress[10] memory keys) =
            codec.exposed_decodeInit(payload);

        assertEq(pq.publicSeed, bytes32(uint256(42)));
        assertEq(pq.publicKeyHash, bytes32(uint256(43)));
        for (uint256 i = 0; i < 10; i++) {
            assertEq(keys[i].publicSeed, bytes32(uint256(42 + 100 + i * 2)));
            assertEq(keys[i].publicKeyHash, bytes32(uint256(42 + 101 + i * 2)));
        }
    }

    function test_exposed_decodeInit_extraBytes_ignored() public view {
        bytes memory payload = _buildInitPayload(42);
        payload = abi.encodePacked(payload, bytes32(uint256(0xFF)), bytes32(uint256(0xFF)), bytes32(uint256(0xFF)));
        (WOTSPlus.WinternitzAddress memory pq,) = codec.exposed_decodeInit(payload);
        assertEq(pq.publicSeed, bytes32(uint256(42)));
    }

    function test_exposed_decodeInit_handlesMaxValues() public view {
        bytes memory payload = abi.encodePacked(
            bytes32(type(uint256).max), bytes32(type(uint256).max)
        );
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, bytes32(type(uint256).max), bytes32(type(uint256).max));
        }
        (WOTSPlus.WinternitzAddress memory pq,) = codec.exposed_decodeInit(payload);
        assertEq(pq.publicSeed, bytes32(type(uint256).max));
        assertEq(pq.publicKeyHash, bytes32(type(uint256).max));
    }

    function test_exposed_decodeInit_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeInit("");
    }

    function test_exposed_decodeInit_revertsWhen_truncatedPayload() public {
        bytes memory payload = abi.encodePacked(bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert();
        codec.exposed_decodeInit(payload);
    }
}
