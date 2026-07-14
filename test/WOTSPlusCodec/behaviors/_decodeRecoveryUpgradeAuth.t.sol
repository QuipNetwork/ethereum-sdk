// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeRecoveryUpgradeAuth is WOTSPlusCodecTest {
    /// @dev Build a 4480-byte recoveryUpgrade payload.
    ///      Layout: currentRecoveryKey(64) + newRecoveryKey(64) + pqSig(2144) +
    ///              verifier(64) + verifySig(2144).
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

    function test_exposed_decodeRecoveryUpgradeAuth_decodesCurrentKey() public view {
        bytes memory payload = _buildRecoveryUpgradePayload(7);
        (WOTSPlus.WinternitzAddress memory cur,,) = codec.exposed_decodeRecoveryUpgradeAuth(payload);
        assertEq(cur.publicSeed, bytes32(uint256(7)));
        assertEq(cur.publicKeyHash, bytes32(uint256(8)));
    }

    function test_exposed_decodeRecoveryUpgradeAuth_decodesNewKey() public view {
        bytes memory payload = _buildRecoveryUpgradePayload(7);
        (, WOTSPlus.WinternitzAddress memory nxt,) = codec.exposed_decodeRecoveryUpgradeAuth(payload);
        assertEq(nxt.publicSeed, bytes32(uint256(9)));
        assertEq(nxt.publicKeyHash, bytes32(uint256(10)));
    }

    function test_exposed_decodeRecoveryUpgradeAuth_decodesPqSig() public view {
        bytes memory payload = _buildRecoveryUpgradePayload(7);
        (,, WOTSPlus.WinternitzElements memory sig) = codec.exposed_decodeRecoveryUpgradeAuth(payload);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(7 + 1000 + i)));
        }
    }

    function test_exposed_decodeRecoveryUpgradeAuth_revertsWhen_emptyPayload() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 4480, 0));
        codec.exposed_decodeRecoveryUpgradeAuth("");
    }

    function test_exposed_decodeRecoveryUpgradeAuth_revertsWhen_wrongLength() public {
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 4480, 4479));
        codec.exposed_decodeRecoveryUpgradeAuth(_filledBytes(4479));
    }

    /// @dev Property: any payload length other than 4480 reverts.
    function testFuzz_exposed_decodeRecoveryUpgradeAuth_revertsWhen_wrongLength(uint256 len) public {
        len = bound(len, 0, 8000);
        vm.assume(len != 4480);
        vm.expectRevert(abi.encodeWithSelector(WOTSPlusCodec.MalformedPayload.selector, 4480, len));
        codec.exposed_decodeRecoveryUpgradeAuth(_filledBytes(len));
    }
}
