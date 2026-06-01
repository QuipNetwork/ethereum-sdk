// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../contracts/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeUpgradeAuth is WOTSPlusCodecTest {
    function test_exposed_decodeUpgradeAuth_decodesCurrentKey() public view {
        bytes memory payload = _buildUpgradePayload(7);
        (WOTSPlus.WinternitzAddress memory cur, , ) = codec
            .exposed_decodeUpgradeAuth(payload);
        assertEq(cur.publicSeed, bytes32(uint256(7)));
        assertEq(cur.publicKeyHash, bytes32(uint256(8)));
    }

    function test_exposed_decodeUpgradeAuth_decodesNextKey() public view {
        bytes memory payload = _buildUpgradePayload(7);
        (, WOTSPlus.WinternitzAddress memory nxt, ) = codec
            .exposed_decodeUpgradeAuth(payload);
        assertEq(nxt.publicSeed, bytes32(uint256(9)));
        assertEq(nxt.publicKeyHash, bytes32(uint256(10)));
    }

    function test_exposed_decodeUpgradeAuth_decodesPqSig() public view {
        bytes memory payload = _buildUpgradePayload(7);
        (, , WOTSPlus.WinternitzElements memory sig) = codec
            .exposed_decodeUpgradeAuth(payload);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(7 + 1000 + i)));
        }
    }

    function test_exposed_decodeUpgradeAuth_revertsWhen_emptyPayload() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                6529,
                0
            )
        );
        codec.exposed_decodeUpgradeAuth("");
    }

    function test_exposed_decodeUpgradeAuth_revertsWhen_wrongLength() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                6529,
                2272
            )
        );
        codec.exposed_decodeUpgradeAuth(_filledBytes(2272));
    }

    /// @dev Property: any payload length other than 6529 reverts.
    function testFuzz_exposed_decodeUpgradeAuth_revertsWhen_wrongLength(
        uint256 len
    ) public {
        len = bound(len, 0, 9000);
        vm.assume(len != 6529);
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                6529,
                len
            )
        );
        codec.exposed_decodeUpgradeAuth(_filledBytes(len));
    }
}
