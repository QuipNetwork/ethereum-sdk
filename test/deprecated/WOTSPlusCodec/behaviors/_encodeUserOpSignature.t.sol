// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeUserOpSignature is WOTSPlusCodecTest {
    function test_exposed_encodeUserOpSignature_roundtrip() public view {
        bytes memory payload = _buildAuthPrefixPayload(77);
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            WOTSPlus.WinternitzElements memory sig
        ) = codec.exposed_decodeUserOpSignature(payload);

        bytes memory encoded = codec.exposed_encodeUserOpSignature(cur, nxt, sig);

        (
            WOTSPlus.WinternitzAddress memory cur2,
            WOTSPlus.WinternitzAddress memory nxt2,
            WOTSPlus.WinternitzElements memory sig2
        ) = codec.exposed_decodeUserOpSignature(encoded);
        assertEq(cur2.publicSeed, cur.publicSeed);
        assertEq(cur2.publicKeyHash, cur.publicKeyHash);
        assertEq(nxt2.publicSeed, nxt.publicSeed);
        assertEq(nxt2.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig2.elements[i], sig.elements[i]);
        }
    }

    function test_exposed_encodeUserOpSignature_producesCorrectLength() public view {
        bytes memory payload = _buildAuthPrefixPayload(77);
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            WOTSPlus.WinternitzElements memory sig
        ) = codec.exposed_decodeUserOpSignature(payload);
        bytes memory encoded = codec.exposed_encodeUserOpSignature(cur, nxt, sig);
        assertEq(encoded.length, 2272);
    }

    /// @dev Property: encode → decode preserves every field for any seed.
    ///      Pins the 2272-byte UserOp signature layout against drift.
    function testFuzz_exposed_encodeUserOpSignature_roundtrips(bytes32 seed) public view {
        WOTSPlus.WinternitzAddress memory cur = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory nxt = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzElements memory sig = _fuzzWinternitzElements(seed);

        bytes memory encoded = codec.exposed_encodeUserOpSignature(cur, nxt, sig);
        assertEq(encoded.length, 2272);

        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig
        ) = codec.exposed_decodeUserOpSignature(encoded);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dCur.publicKeyHash, cur.publicKeyHash);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
    }
}
