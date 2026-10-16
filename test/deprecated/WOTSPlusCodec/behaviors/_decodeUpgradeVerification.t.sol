// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeUpgradeVerification is WOTSPlusCodecTest {
    function test_exposed_decodeUpgradeVerification_decodesVerifier() public view {
        bytes memory payload = _buildUpgradePayload(7);
        (WOTSPlus.WinternitzAddress memory v,) = codec.exposed_decodeUpgradeVerification(payload);
        assertEq(v.publicSeed, bytes32(uint256(7 + 2000)));
        assertEq(v.publicKeyHash, bytes32(uint256(7 + 2001)));
    }

    function test_exposed_decodeUpgradeVerification_decodesVerifySig() public view {
        bytes memory payload = _buildUpgradePayload(7);
        (, WOTSPlus.WinternitzElements memory sig) = codec.exposed_decodeUpgradeVerification(payload);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(7 + 3000 + i)));
        }
    }

    function test_exposed_decodeUpgradeVerification_revertsWhen_emptyPayload() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 6529, 0));
        codec.exposed_decodeUpgradeVerification("");
    }

    function test_exposed_decodeUpgradeVerification_revertsWhen_wrongLength() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 6529, 4480));
        codec.exposed_decodeUpgradeVerification(_filledBytes(4480));
    }

    /// @dev Property: any payload length other than 6529 reverts.
    function testFuzz_exposed_decodeUpgradeVerification_revertsWhen_wrongLength(uint256 len) public {
        len = bound(len, 0, 9000);
        vm.assume(len != 6529);
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 6529, len));
        codec.exposed_decodeUpgradeVerification(_filledBytes(len));
    }
}
