// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeExecute is WOTSPlusCodecTest {
    function test_exposed_encodeExecute_producesCorrectLength() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        bytes memory data = hex"aabb";
        bytes memory encoded = codec.exposed_encodeExecute(
            cur,
            nxt,
            sig,
            address(0xBEEF),
            1 ether,
            data
        );
        assertEq(encoded.length, 2336 + data.length);
    }

    function test_exposed_encodeExecute_roundtrips() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        for (uint256 i = 0; i < 67; i++) sig.elements[i] = bytes32(i + 100);
        address target = address(0xBEEF);
        uint256 value = 1.5 ether;
        bytes memory data = hex"deadbeef";

        bytes memory encoded = codec.exposed_encodeExecute(
            cur,
            nxt,
            sig,
            target,
            value,
            data
        );
        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            ,
            address dT,
            uint256 dV,
            bytes memory dD
        ) = codec.exposed_decodeExecute(encoded);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dT, target);
        assertEq(dV, value);
        assertEq(dD, data);
    }

    function test_exposed_encodeExecute_roundtripsEmptyData() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        bytes memory encoded = codec.exposed_encodeExecute(
            cur,
            nxt,
            sig,
            address(0x1),
            0,
            ""
        );
        assertEq(encoded.length, 2336);
        (, , , , , bytes memory dD) = codec.exposed_decodeExecute(encoded);
        assertEq(dD.length, 0);
    }
}
