// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeKeyManagement is WOTSPlusCodecTest {
    function test_exposed_decodeKeyManagement_decodesWithMultipleKeys() public view {
        bytes memory payload = _buildKeyManagementPayload(30, 3);
        (
            WOTSPlus.WinternitzAddress memory pq,,
            WOTSPlus.WinternitzAddress[] memory keys
        ) = codec.exposed_decodeKeyManagement(payload);

        assertEq(pq.publicSeed, bytes32(uint256(30)));
        assertEq(keys.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertEq(keys[i].publicSeed, bytes32(uint256(30 + 500 + i * 2)));
            assertEq(keys[i].publicKeyHash, bytes32(uint256(30 + 501 + i * 2)));
        }
    }

    function test_exposed_decodeKeyManagement_decodesWithZeroKeys() public view {
        bytes memory payload = _buildKeyManagementPayload(30, 0);
        (,, WOTSPlus.WinternitzAddress[] memory keys) = codec.exposed_decodeKeyManagement(payload);
        assertEq(keys.length, 0);
    }

    function test_exposed_decodeKeyManagement_decodesWithMaxKeys() public view {
        bytes memory payload = _buildKeyManagementPayload(30, 10);
        (,, WOTSPlus.WinternitzAddress[] memory keys) = codec.exposed_decodeKeyManagement(payload);
        assertEq(keys.length, 10);
    }
}
