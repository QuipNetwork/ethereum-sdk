// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeUserOpSignature is WOTSPlusCodecTest {
    function test_exposed_encodeUserOpSignature_roundtrip() public view {
        bytes memory payload = _buildChangeTransactionKeyPayload(77);
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            WOTSPlus.WinternitzElements memory sig
        ) = codec.exposed_decodeChangeTransactionKey(payload);

        bytes memory encoded = codec.exposed_encodeUserOpSignature(
            cur,
            nxt,
            sig
        );

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

    function test_exposed_encodeUserOpSignature_producesCorrectLength()
        public
        view
    {
        bytes memory payload = _buildChangeTransactionKeyPayload(77);
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            WOTSPlus.WinternitzElements memory sig
        ) = codec.exposed_decodeChangeTransactionKey(payload);
        bytes memory encoded = codec.exposed_encodeUserOpSignature(
            cur,
            nxt,
            sig
        );
        assertEq(encoded.length, 2272);
    }
}
