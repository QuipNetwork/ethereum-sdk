// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeKeyManagement is WOTSPlusCodecTest {
    function test_exposed_encodeKeyManagement_producesCorrectLength() public view {
        WOTSPlus.WinternitzAddress memory pq = WOTSPlus.WinternitzAddress(bytes32(uint256(1)), bytes32(uint256(2)));
        WOTSPlus.WinternitzElements memory sig;
        WOTSPlus.WinternitzAddress[] memory keys = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys[i] = WOTSPlus.WinternitzAddress(bytes32(i + 10), bytes32(i + 20));
        }
        bytes memory encoded = codec.exposed_encodeKeyManagement(pq, sig, keys);
        assertEq(encoded.length, 2208 + 3 * 64);
    }

    function test_exposed_encodeKeyManagement_roundtrips() public view {
        WOTSPlus.WinternitzAddress memory pq = WOTSPlus.WinternitzAddress(bytes32(uint256(1)), bytes32(uint256(2)));
        WOTSPlus.WinternitzElements memory sig;
        for (uint256 i = 0; i < 67; i++) sig.elements[i] = bytes32(i + 200);
        WOTSPlus.WinternitzAddress[] memory keys = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys[i] = WOTSPlus.WinternitzAddress(bytes32(i + 10), bytes32(i + 20));
        }

        bytes memory encoded = codec.exposed_encodeKeyManagement(pq, sig, keys);
        (
            WOTSPlus.WinternitzAddress memory dPq,,
            WOTSPlus.WinternitzAddress[] memory dKeys
        ) = codec.exposed_decodeKeyManagement(encoded);

        assertEq(dPq.publicSeed, pq.publicSeed);
        assertEq(dKeys.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertEq(dKeys[i].publicSeed, keys[i].publicSeed);
            assertEq(dKeys[i].publicKeyHash, keys[i].publicKeyHash);
        }
    }

    function test_exposed_encodeKeyManagement_roundtripsEmptyKeys() public view {
        WOTSPlus.WinternitzAddress memory pq = WOTSPlus.WinternitzAddress(bytes32(uint256(1)), bytes32(uint256(2)));
        WOTSPlus.WinternitzElements memory sig;
        WOTSPlus.WinternitzAddress[] memory keys = new WOTSPlus.WinternitzAddress[](0);
        bytes memory encoded = codec.exposed_encodeKeyManagement(pq, sig, keys);
        assertEq(encoded.length, 2208);
        (,, WOTSPlus.WinternitzAddress[] memory dKeys) = codec.exposed_decodeKeyManagement(encoded);
        assertEq(dKeys.length, 0);
    }
}
