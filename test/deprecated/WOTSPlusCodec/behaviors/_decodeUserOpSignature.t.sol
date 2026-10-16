// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeUserOpSignature is WOTSPlusCodecTest {
    function test_exposed_decodeUserOpSignature_decodesCorrectly() public view {
        bytes memory payload = _buildAuthPrefixPayload(55);
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            WOTSPlus.WinternitzElements memory sig
        ) = codec.exposed_decodeUserOpSignature(payload);

        assertEq(cur.publicSeed, bytes32(uint256(55)));
        assertEq(cur.publicKeyHash, bytes32(uint256(56)));
        assertEq(nxt.publicSeed, bytes32(uint256(57)));
        assertEq(nxt.publicKeyHash, bytes32(uint256(58)));
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(55 + 100 + i)));
        }
    }

    function test_exposed_decodeUserOpSignature_revertsWhen_emptyPayload() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 2272, 0));
        codec.exposed_decodeUserOpSignature("");
    }

    function test_exposed_decodeUserOpSignature_revertsWhen_wrongLength() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 2272, 2271));
        codec.exposed_decodeUserOpSignature(_filledBytes(2271));
    }

    /// @dev Property: any payload length other than 2272 reverts. The
    ///      signature comes straight off ERC-4337 calldata, so the length
    ///      precondition is the first attacker-controllable boundary.
    function testFuzz_exposed_decodeUserOpSignature_revertsWhen_wrongLength(uint256 len) public {
        len = bound(len, 0, 5000);
        vm.assume(len != 2272);
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 2272, len));
        codec.exposed_decodeUserOpSignature(_filledBytes(len));
    }
}
