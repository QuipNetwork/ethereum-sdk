// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeChangePqOwner is WOTSPlusCodecTest {
    function test_exposed_encodeChangePqOwner_producesCorrectLength() public view {
        (WOTSPlus.WinternitzAddress memory pq, WOTSPlus.WinternitzElements memory sig) =
            _makeKeyAndSig(1);
        bytes memory encoded = codec.exposed_encodeChangePqOwner(pq, sig);
        assertEq(encoded.length, 2208);
    }

    function test_exposed_encodeChangePqOwner_roundtrips() public view {
        (WOTSPlus.WinternitzAddress memory pq, WOTSPlus.WinternitzElements memory sig) =
            _makeKeyAndSig(1);
        bytes memory encoded = codec.exposed_encodeChangePqOwner(pq, sig);
        (WOTSPlus.WinternitzAddress memory dPq, WOTSPlus.WinternitzElements memory dSig) =
            codec.exposed_decodeChangePqOwner(encoded);
        assertEq(dPq.publicSeed, pq.publicSeed);
        assertEq(dPq.publicKeyHash, pq.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
    }

    function _makeKeyAndSig(uint256 seed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory pq, WOTSPlus.WinternitzElements memory sig)
    {
        pq = WOTSPlus.WinternitzAddress(bytes32(seed), bytes32(seed + 1));
        for (uint256 i = 0; i < 67; i++) {
            sig.elements[i] = bytes32(seed + 100 + i);
        }
    }
}
