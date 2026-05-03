// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../contracts/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeInit is WOTSPlusCodecTest {
    function test_exposed_decodeInit_decodesCorrectly() public view {
        bytes memory payload = _buildInitPayload(42);
        (
            WOTSPlus.WinternitzAddress memory disasterKey,
            WOTSPlus.WinternitzAddress memory ownershipKey,
            WOTSPlus.WinternitzAddress[5] memory txnKeys,
            WOTSPlus.WinternitzAddress[10] memory recKeys
        ) = codec.exposed_decodeInit(payload);

        assertEq(disasterKey.publicSeed, bytes32(uint256(42 + 500)));
        assertEq(disasterKey.publicKeyHash, bytes32(uint256(42 + 501)));
        assertEq(ownershipKey.publicSeed, bytes32(uint256(42 + 600)));
        assertEq(ownershipKey.publicKeyHash, bytes32(uint256(42 + 601)));
        for (uint256 i = 0; i < 5; i++) {
            assertEq(txnKeys[i].publicSeed, bytes32(uint256(42 + i * 2)));
            assertEq(
                txnKeys[i].publicKeyHash,
                bytes32(uint256(42 + 1 + i * 2))
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(recKeys[i].publicSeed, bytes32(uint256(42 + 100 + i * 2)));
            assertEq(
                recKeys[i].publicKeyHash,
                bytes32(uint256(42 + 101 + i * 2))
            );
        }
    }

    function test_exposed_decodeInit_revertsWhen_extraBytes() public {
        bytes memory payload = _buildInitPayload(42);
        payload = abi.encodePacked(
            payload,
            bytes32(uint256(0xFF)),
            bytes32(uint256(0xFF)),
            bytes32(uint256(0xFF))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                1088,
                1184
            )
        );
        codec.exposed_decodeInit(payload);
    }

    function test_exposed_decodeInit_handlesMaxValues() public view {
        bytes memory payload = new bytes(0);
        // disaster (2) + ownership (2) + txn (10) + rec (20) = 34 bytes32 slots.
        for (uint256 i = 0; i < 34; i++) {
            payload = abi.encodePacked(payload, bytes32(type(uint256).max));
        }
        (, , WOTSPlus.WinternitzAddress[5] memory txnKeys, ) = codec
            .exposed_decodeInit(payload);
        assertEq(txnKeys[0].publicSeed, bytes32(type(uint256).max));
        assertEq(txnKeys[0].publicKeyHash, bytes32(type(uint256).max));
    }

    function test_exposed_decodeInit_revertsWhen_emptyPayload() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                1088,
                0
            )
        );
        codec.exposed_decodeInit("");
    }

    function test_exposed_decodeInit_revertsWhen_truncatedPayload() public {
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                1088,
                64
            )
        );
        codec.exposed_decodeInit(payload);
    }

    /// @dev Property: any payload length other than 1088 reverts with
    ///      MalformedPayload(1088, length). Fuzz across the full range to
    ///      exhaust off-by-N drift in the length precondition.
    function testFuzz_exposed_decodeInit_revertsWhen_wrongLength(
        uint256 len
    ) public {
        len = bound(len, 0, 4000);
        vm.assume(len != 1088);
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                1088,
                len
            )
        );
        codec.exposed_decodeInit(_filledBytes(len));
    }
}
