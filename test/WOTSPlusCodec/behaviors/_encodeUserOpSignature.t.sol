// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeUserOpSignature is WOTSPlusCodecTest {
    function test_exposed_encodeUserOpSignature_roundtrip() public view {
        bytes memory changePqPayload = _buildChangePqOwnerPayload(77);
        (WOTSPlus.WinternitzAddress memory pq, WOTSPlus.WinternitzElements memory sig) =
            codec.exposed_decodeChangePqOwner(changePqPayload);

        bytes memory encoded = codec.exposed_encodeUserOpSignature(pq, sig);

        (WOTSPlus.WinternitzAddress memory pq2, WOTSPlus.WinternitzElements memory sig2) =
            codec.exposed_decodeUserOpSignature(encoded);
        assertEq(pq2.publicSeed, pq.publicSeed);
        assertEq(pq2.publicKeyHash, pq.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig2.elements[i], sig.elements[i]);
        }
    }

    function test_exposed_encodeUserOpSignature_producesCorrectLength() public view {
        bytes memory changePqPayload = _buildChangePqOwnerPayload(77);
        (WOTSPlus.WinternitzAddress memory pq, WOTSPlus.WinternitzElements memory sig) =
            codec.exposed_decodeChangePqOwner(changePqPayload);
        bytes memory encoded = codec.exposed_encodeUserOpSignature(pq, sig);
        assertEq(encoded.length, 2208);
    }
}
