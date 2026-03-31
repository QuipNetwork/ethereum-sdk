// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeUpgradeAuth is WOTSPlusCodecTest {
    function test_exposed_decodeUpgradeAuth_decodesNextPqOwner() public view {
        bytes memory payload = _buildUpgradePayload(7);
        (WOTSPlus.WinternitzAddress memory pq,) = codec.exposed_decodeUpgradeAuth(payload);
        assertEq(pq.publicSeed, bytes32(uint256(7)));
        assertEq(pq.publicKeyHash, bytes32(uint256(8)));
    }

    function test_exposed_decodeUpgradeAuth_decodesPqSig() public view {
        bytes memory payload = _buildUpgradePayload(7);
        (, WOTSPlus.WinternitzElements memory sig) = codec.exposed_decodeUpgradeAuth(payload);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(7 + 1000 + i)));
        }
    }
}
