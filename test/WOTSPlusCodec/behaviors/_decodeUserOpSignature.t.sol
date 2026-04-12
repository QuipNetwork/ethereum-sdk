// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeUserOpSignature is WOTSPlusCodecTest {
    function test_exposed_decodeUserOpSignature_decodesCorrectly() public view {
        bytes memory payload = _buildChangePqOwnerPayload(55);
        (WOTSPlus.WinternitzAddress memory pq, WOTSPlus.WinternitzElements memory sig) =
            codec.exposed_decodeUserOpSignature(payload);

        assertEq(pq.publicSeed, bytes32(uint256(55)));
        assertEq(pq.publicKeyHash, bytes32(uint256(56)));
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(55 + 100 + i)));
        }
    }

    function test_exposed_decodeUserOpSignature_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeUserOpSignature("");
    }
}
