// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeErc1271Signature is WOTSPlusCodecTest {
    /// @dev Build a 2273-byte ERC-1271 signature payload.
    ///      Layout: verifier(64) + pqSig(2144) + ecdsaSig(65).
    function _buildErc1271Payload(
        uint256 seed
    ) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(bytes32(seed), bytes32(seed + 1));
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 100 + i));
        }
        // 65-byte ECDSA sig (r ++ s ++ v)
        payload = abi.encodePacked(
            payload,
            bytes32(seed + 1000), // r
            bytes32(seed + 1001), // s
            uint8(27) // v
        );
    }

    function test_exposed_decodeErc1271Signature_decodesVerifier() public view {
        bytes memory payload = _buildErc1271Payload(42);
        (WOTSPlus.WinternitzAddress memory v, , ) = codec
            .exposed_decodeErc1271Signature(payload);
        assertEq(v.publicSeed, bytes32(uint256(42)));
        assertEq(v.publicKeyHash, bytes32(uint256(43)));
    }

    function test_exposed_decodeErc1271Signature_decodesPqSig() public view {
        bytes memory payload = _buildErc1271Payload(42);
        (, WOTSPlus.WinternitzElements memory sig, ) = codec
            .exposed_decodeErc1271Signature(payload);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(42 + 100 + i)));
        }
    }

    function test_exposed_decodeErc1271Signature_decodesEcdsaSig() public view {
        bytes memory payload = _buildErc1271Payload(42);
        (, , bytes memory ecdsa) = codec.exposed_decodeErc1271Signature(payload);
        assertEq(ecdsa.length, 65);
        // First 32 bytes = r.
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(ecdsa, 32))
            s := mload(add(ecdsa, 64))
            v := byte(0, mload(add(ecdsa, 96)))
        }
        assertEq(r, bytes32(uint256(42 + 1000)));
        assertEq(s, bytes32(uint256(42 + 1001)));
        assertEq(v, 27);
    }

    function test_exposed_decodeErc1271Signature_revertsWhen_truncatedPayload()
        public
    {
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                2273,
                2200
            )
        );
        codec.exposed_decodeErc1271Signature(_filledBytes(2200));
    }

    function test_exposed_decodeErc1271Signature_revertsWhen_extraBytes()
        public
    {
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                2273,
                2274
            )
        );
        codec.exposed_decodeErc1271Signature(_filledBytes(2274));
    }

    /// @dev Property: any payload length other than 2273 reverts. The
    ///      signature comes off `isValidSignature` calldata and is the first
    ///      attacker-controllable input, so the precondition is load-bearing.
    function testFuzz_exposed_decodeErc1271Signature_revertsWhen_wrongLength(
        uint256 len
    ) public {
        len = bound(len, 0, 5000);
        vm.assume(len != 2273);
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                2273,
                len
            )
        );
        codec.exposed_decodeErc1271Signature(_filledBytes(len));
    }
}
