// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

contract ShrincsWalletCodec_decodeProbePayload is ShrincsWalletCodecTest {
    function test_decodeProbePayload_roundTrip() public view {
        SHRINCS.PublicKey memory pk = _samplePublicKey();
        SHRINCS.Signature memory statefulSig = _sampleStatefulSig();
        bytes memory statelessSig = _sampleStatelessSig();
        bytes memory payload = abi.encode(pk, statefulSig, statelessSig);

        (
            SHRINCS.PublicKey memory dpk,
            SHRINCS.Signature memory dStateful,
            bytes memory dStateless
        ) = codec.exposed_decodeProbePayload(payload);

        _assertPkEq(dpk, pk);
        _assertStatefulSigEq(dStateful, statefulSig);
        assertEq(dStateless, statelessSig, "stateless sig round-trips");
    }

    function test_decodeProbePayload_revertsWhen_tooShort() public {
        // A 2-word head is one word short of the 0x60 floor.
        bytes memory short = new bytes(0x40);
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x60, 0x40));
        codec.exposed_decodeProbePayload(short);
    }

    function test_decodeProbePayload_revertsWhen_tailOffsetOutOfBounds() public {
        // Head is 0x60 (three words); word[0] is the bundle tail offset — send it past the end.
        bytes memory payload = bytes.concat(bytes32(uint256(0x60)), bytes32(0), bytes32(0));
        // Reading the pointed-to head word needs 0x60 + 0x20 = 0x80 bytes; the slice is 0x60.
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 0x80, 0x60));
        codec.exposed_decodeProbePayload(payload);
    }

    /// @dev A well-formed probe vector whose `statelessSig` is `dataLen` zero bytes. `dataLen` is a
    ///      multiple of 32, so the ABI tail carries no padding and the bytes end at the payload end.
    function _probeWithStatelessLen(uint256 dataLen) internal pure returns (bytes memory) {
        return abi.encode(_samplePublicKey(), _sampleStatefulSig(), new bytes(dataLen));
    }

    /// @dev Overwrites the 32-byte word at `offset` in `payload`.
    function _setWord(bytes memory payload, uint256 offset, uint256 value) internal pure {
        assembly {
            mstore(add(add(payload, 0x20), offset), value)
        }
    }

    /// @dev Offset of the `statelessSig` length word (the third head word).
    function _statelessOffset(bytes memory payload) internal pure returns (uint256 slo) {
        assembly {
            slo := mload(add(payload, 0x60))
        }
    }

    function test_decodeProbePayload_statelessSigExactFit() public view {
        bytes memory payload = _probeWithStatelessLen(0x40);
        assertEq(_statelessOffset(payload) + 0x20 + 0x40, payload.length, "fixture: bytes end at the payload end");
        (,, bytes memory dStateless) = codec.exposed_decodeProbePayload(payload);
        assertEq(dStateless, new bytes(0x40), "exact-fit stateless sig decodes");
    }

    /// @dev A real probe always carries a stateless signature of `StatelessLayout.PQ_LEN` bytes.
    ///      The DECODER only proves the bytes lie inside the payload; it does not judge their
    ///      length, which the verifier checks. So a zero-length field decodes here and is then
    ///      rejected by `verifyUpgrade` (`test_verifyUpgrade_revertsWhen_statelessSigEmpty`).
    function test_decodeProbePayload_leavesStatelessSigLengthToVerifier() public view {
        (,, bytes memory dStateless) = codec.exposed_decodeProbePayload(_probeWithStatelessLen(0));
        assertEq(dStateless.length, 0, "zero-length stateless sig is framed, not validated");
    }

    function test_decodeProbePayload_revertsWhen_statelessSigOverrunsPayload() public {
        // The length word claims one byte more than the payload holds.
        bytes memory payload = _probeWithStatelessLen(0x40);
        uint256 slo = _statelessOffset(payload);
        _setWord(payload, slo, 0x41);
        vm.expectRevert(
            abi.encodeWithSelector(Codec.MalformedPayload.selector, payload.length + 1, payload.length)
        );
        codec.exposed_decodeProbePayload(payload);
    }

    function test_decodeProbePayload_revertsWhen_statelessSigLengthOverflows() public {
        // A max-value length must not wrap the fit check. The diagnostic `expected`
        // (slo + 0x20 + length) does wrap mod 2^256, to slo + 0x1f.
        bytes memory payload = _probeWithStatelessLen(0x40);
        uint256 slo = _statelessOffset(payload);
        _setWord(payload, slo, type(uint256).max);
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, slo + 0x1f, payload.length));
        codec.exposed_decodeProbePayload(payload);
    }

    function test_decodeProbePayload_revertsWhen_statelessSigOffsetOutOfBounds() public {
        // Third offset points at the payload end, so its length word is out of range.
        bytes memory payload = _probeWithStatelessLen(0x40);
        _setWord(payload, 0x40, payload.length);
        vm.expectRevert(
            abi.encodeWithSelector(Codec.MalformedPayload.selector, payload.length + 0x20, payload.length)
        );
        codec.exposed_decodeProbePayload(payload);
    }
}
