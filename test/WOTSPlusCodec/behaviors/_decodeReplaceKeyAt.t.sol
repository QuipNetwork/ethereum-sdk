// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeReplaceKeyAt is WOTSPlusCodecTest {
    /// @dev Build a 2400-byte replaceKeyAt payload.
    ///      Layout: kind(32) + currentKey(64) + nextKey(64) + pqSig(2144) +
    ///              index(32) + newKey(64).
    function _buildReplaceKeyAtPayload(
        uint256 seed,
        Codec.KeyType kind,
        uint256 index
    ) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(bytes32(uint256(kind)));
        payload = abi.encodePacked(
            payload,
            _buildAuthPrefixPayload(seed)
        );
        payload = abi.encodePacked(payload, bytes32(index));
        payload = abi.encodePacked(
            payload,
            bytes32(seed + 500),
            bytes32(seed + 501)
        );
    }

    function test_exposed_decodeReplaceKeyAt_decodesTransactionKind()
        public
        view
    {
        bytes memory payload = _buildReplaceKeyAtPayload(
            30,
            Codec.KeyType.Transaction,
            2
        );
        (
            Codec.KeyType kind,
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            WOTSPlus.WinternitzElements memory sig,
            uint256 idx,
            WOTSPlus.WinternitzAddress memory newKey
        ) = codec.exposed_decodeReplaceKeyAt(payload);

        assertTrue(kind == Codec.KeyType.Transaction);
        assertEq(cur.publicSeed, bytes32(uint256(30)));
        assertEq(cur.publicKeyHash, bytes32(uint256(31)));
        assertEq(nxt.publicSeed, bytes32(uint256(32)));
        assertEq(nxt.publicKeyHash, bytes32(uint256(33)));
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(30 + 100 + i)));
        }
        assertEq(idx, 2);
        assertEq(newKey.publicSeed, bytes32(uint256(30 + 500)));
        assertEq(newKey.publicKeyHash, bytes32(uint256(30 + 501)));
    }

    function test_exposed_decodeReplaceKeyAt_decodesRecoveryKind() public view {
        bytes memory payload = _buildReplaceKeyAtPayload(
            30,
            Codec.KeyType.Recovery,
            5
        );
        (Codec.KeyType kind, , , , uint256 idx, ) = codec
            .exposed_decodeReplaceKeyAt(payload);
        assertTrue(kind == Codec.KeyType.Recovery);
        assertEq(idx, 5);
    }

    function test_exposed_decodeReplaceKeyAt_decodesVerificationKind()
        public
        view
    {
        bytes memory payload = _buildReplaceKeyAtPayload(
            30,
            Codec.KeyType.Verification,
            0
        );
        (Codec.KeyType kind, , , , uint256 idx, ) = codec
            .exposed_decodeReplaceKeyAt(payload);
        assertTrue(kind == Codec.KeyType.Verification);
        assertEq(idx, 0);
    }

    function test_exposed_decodeReplaceKeyAt_revertsWhen_kindOutOfRange()
        public
    {
        // A filled 2400-byte payload has a leading 0xAB…AB kind value far
        // out of the KeyType enum range; the implicit enum cast must revert.
        bytes memory payload = _filledBytes(2400);
        vm.expectRevert();
        codec.exposed_decodeReplaceKeyAt(payload);
    }

    function test_exposed_decodeReplaceKeyAt_revertsWhen_emptyPayload() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2400,
                0
            )
        );
        codec.exposed_decodeReplaceKeyAt("");
    }

    function test_exposed_decodeReplaceKeyAt_revertsWhen_truncatedPayload()
        public
    {
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2400,
                2000
            )
        );
        codec.exposed_decodeReplaceKeyAt(_filledBytes(2000));
    }

    function test_exposed_decodeReplaceKeyAt_revertsWhen_extraBytes() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2400,
                2401
            )
        );
        codec.exposed_decodeReplaceKeyAt(_filledBytes(2401));
    }

    /// @dev Property: any payload length other than 2400 reverts. The length
    ///      precondition fires before the enum cast, so the kind byte content
    ///      doesn't matter here.
    function testFuzz_exposed_decodeReplaceKeyAt_revertsWhen_wrongLength(
        uint256 len
    ) public {
        len = bound(len, 0, 5000);
        vm.assume(len != 2400);
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2400,
                len
            )
        );
        codec.exposed_decodeReplaceKeyAt(_filledBytes(len));
    }
}
