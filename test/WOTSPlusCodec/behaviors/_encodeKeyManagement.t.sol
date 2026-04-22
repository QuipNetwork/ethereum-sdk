// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeKeyManagement is WOTSPlusCodecTest {
    function test_exposed_encodeKeyManagement_producesCorrectLength()
        public
        view
    {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys[i] = WOTSPlus.WinternitzAddress(
                bytes32(i + 10),
                bytes32(i + 20)
            );
        }
        bytes memory encoded = codec.exposed_encodeKeyManagement(
            Codec.KeyType.Recovery,
            cur,
            nxt,
            sig,
            keys
        );
        // 32 (kind) + 64 (cur) + 64 (nxt) + 2144 (sig) + 3 * 64
        assertEq(encoded.length, 32 + 64 + 64 + 2144 + 3 * 64);
    }

    function test_exposed_encodeKeyManagement_roundtrips() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        for (uint256 i = 0; i < 67; i++) sig.elements[i] = bytes32(i + 200);
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys[i] = WOTSPlus.WinternitzAddress(
                bytes32(i + 10),
                bytes32(i + 20)
            );
        }

        bytes memory encoded = codec.exposed_encodeKeyManagement(
            Codec.KeyType.Verification,
            cur,
            nxt,
            sig,
            keys
        );
        (
            Codec.KeyType kind,
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            ,
            WOTSPlus.WinternitzAddress[] memory dKeys
        ) = codec.exposed_decodeKeyManagement(encoded);

        assertTrue(kind == Codec.KeyType.Verification);
        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dKeys.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertEq(dKeys[i].publicSeed, keys[i].publicSeed);
            assertEq(dKeys[i].publicKeyHash, keys[i].publicKeyHash);
        }
    }

    function test_exposed_encodeKeyManagement_roundtripsEmptyKeys()
        public
        view
    {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](0);
        bytes memory encoded = codec.exposed_encodeKeyManagement(
            Codec.KeyType.Transaction,
            cur,
            nxt,
            sig,
            keys
        );
        assertEq(encoded.length, 32 + 64 + 64 + 2144);
        (
            Codec.KeyType kind,
            ,
            ,
            ,
            WOTSPlus.WinternitzAddress[] memory dKeys
        ) = codec.exposed_decodeKeyManagement(encoded);
        assertTrue(kind == Codec.KeyType.Transaction);
        assertEq(dKeys.length, 0);
    }
}
