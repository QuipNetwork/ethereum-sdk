// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeRecoveryUpgradeVerification is WOTSPlusCodecTest {
    function _buildRecoveryUpgradePayload(uint256 seed) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(bytes32(seed), bytes32(seed + 1));
        payload = abi.encodePacked(payload, bytes32(seed + 2), bytes32(seed + 3));
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 1000 + i));
        }
        payload = abi.encodePacked(payload, bytes32(seed + 2000), bytes32(seed + 2001));
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 3000 + i));
        }
    }

    function test_exposed_decodeRecoveryUpgradeVerification_decodesVerifier() public view {
        bytes memory payload = _buildRecoveryUpgradePayload(7);
        (WOTSPlus.WinternitzAddress memory v,) = codec.exposed_decodeRecoveryUpgradeVerification(payload);
        assertEq(v.publicSeed, bytes32(uint256(7 + 2000)));
        assertEq(v.publicKeyHash, bytes32(uint256(7 + 2001)));
    }

    function test_exposed_decodeRecoveryUpgradeVerification_decodesVerifySig() public view {
        bytes memory payload = _buildRecoveryUpgradePayload(7);
        (, WOTSPlus.WinternitzElements memory sig) = codec.exposed_decodeRecoveryUpgradeVerification(payload);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(7 + 3000 + i)));
        }
    }

    function test_exposed_decodeRecoveryUpgradeVerification_revertsWhen_emptyPayload() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 4480, 0));
        codec.exposed_decodeRecoveryUpgradeVerification("");
    }

    function test_exposed_decodeRecoveryUpgradeVerification_revertsWhen_wrongLength() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 4480, 6529));
        codec.exposed_decodeRecoveryUpgradeVerification(_filledBytes(6529));
    }

    /// @dev Property: any payload length other than 4480 reverts.
    function testFuzz_exposed_decodeRecoveryUpgradeVerification_revertsWhen_wrongLength(uint256 len) public {
        len = bound(len, 0, 8000);
        vm.assume(len != 4480);
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 4480, len));
        codec.exposed_decodeRecoveryUpgradeVerification(_filledBytes(len));
    }
}
