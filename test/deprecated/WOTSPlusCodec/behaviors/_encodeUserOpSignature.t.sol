// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeUserOpSignature is WOTSPlusCodecTest {
    function _sampleUserOpSignature()
        internal
        view
        returns (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            WOTSPlus.WinternitzElements memory sig,
            bytes memory encoded
        )
    {
        bytes memory payload = _buildAuthPrefixPayload(77);
        (cur, nxt, sig) = codec.exposed_decodeUserOpSignature(payload);
        encoded = codec.exposed_encodeUserOpSignature(cur, nxt, sig);
    }

    function test_exposed_encodeUserOpSignature_roundtrip() public view {
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            WOTSPlus.WinternitzElements memory sig,
            bytes memory encoded
        ) = _sampleUserOpSignature();

        (
            WOTSPlus.WinternitzAddress memory cur2,
            WOTSPlus.WinternitzAddress memory nxt2,
            WOTSPlus.WinternitzElements memory sig2
        ) = codec.exposed_decodeUserOpSignature(encoded);
        _assertEqAuthPrefix(cur2, cur, nxt2, nxt, sig2, sig);
    }

    function test_exposed_encodeUserOpSignature_producesCorrectLength() public view {
        (,,, bytes memory encoded) = _sampleUserOpSignature();
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
