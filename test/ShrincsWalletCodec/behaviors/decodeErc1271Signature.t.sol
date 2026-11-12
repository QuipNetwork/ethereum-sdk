// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {ShrincsWalletCodecTest} from "../ShrincsWalletCodec.t.sol";

/// @dev Behavior tests for the fixed-layout ERC-1271 envelope decoder and the layout constants it
///      slices by. The decoder never reverts. It REJECTS a malformed input by returning
///      `ok == false` with empty slices (the `returnsFalseWhen_` tests), so the ERC-1271
///      staticcall path can map it to the failure magic.
contract ShrincsWalletCodec_tryDecodeErc1271Signature is ShrincsWalletCodecTest {
    /// @dev A header-valid envelope whose ECDSA region is filled with 0xec and payload with 0xab,
    ///      so slice boundaries are visible byte-for-byte.
    function _envelope() internal pure returns (bytes memory blob) {
        blob = abi.encodePacked(
            Codec.ERC1271_MAGIC,
            Codec.ERC1271_VERSION,
            SHRINCSParams.PROFILE_ID,
            _filled(Codec.ERC1271_ECDSA_LEN, 0xec),
            _filled(StatelessLayout.PAYLOAD_LEN, 0xab)
        );
    }

    function _filled(uint256 n, uint8 b) internal pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 i; i < n; ++i) {
            out[i] = bytes1(b);
        }
    }

    function _assertRejected(bytes memory blob, string memory why) internal view {
        (bool ok, bytes memory ecdsaSig, bytes memory payload) = codec.exposed_tryDecodeErc1271Signature(blob);
        assertFalse(ok, why);
        assertEq(ecdsaSig.length, 0, "rejected envelope yields an empty ecdsa slice");
        assertEq(payload.length, 0, "rejected envelope yields an empty payload slice");
    }

    /// @dev Pins the wire layout on the 256s profile. A change here is a breaking envelope change
    ///      that the SDK encoder must mirror.
    function test_tryDecodeErc1271Signature_layoutMatches256sTable() public pure {
        assertEq(Codec.ERC1271_MAGIC, bytes4("QPCS"), "magic");
        assertEq(Codec.ERC1271_VERSION, StatelessLayout.ENCODING_VERSION, "version tracks upstream");
        assertEq(Codec.ERC1271_VERSION, 1, "version");
        assertEq(Codec.ERC1271_VERSION_OFF, 4, "version offset");
        assertEq(Codec.ERC1271_PROFILE_OFF, 5, "profile offset");
        assertEq(Codec.ERC1271_HEADER_LEN, 37, "header");
        assertEq(Codec.ERC1271_ECDSA_OFF, 37, "ecdsa offset");
        assertEq(Codec.ERC1271_ECDSA_LEN, 65, "ecdsa length");
        assertEq(Codec.ERC1271_PAYLOAD_OFF, 102, "payload offset");
        assertEq(StatelessLayout.PAYLOAD_LEN, 29_256, "payload");
        assertEq(Codec.ERC1271_TOTAL_LEN, 29_358, "total");
    }

    function test_tryDecodeErc1271Signature_roundTrip() public view {
        (bool ok, bytes memory ecdsaSig, bytes memory payload) = codec.exposed_tryDecodeErc1271Signature(_envelope());
        assertTrue(ok, "well-formed envelope decodes");
        assertEq(ecdsaSig, _filled(65, 0xec), "ecdsa slice is exactly [37, 102)");
        assertEq(payload, _filled(StatelessLayout.PAYLOAD_LEN, 0xab), "payload slice is exactly [102, end)");
    }

    function test_tryDecodeErc1271Signature_returnsFalseWhen_empty() public view {
        _assertRejected("", "empty signature rejected");
    }

    // Kept from the ABI-envelope era: a short blob is rejected without reverting.
    function test_tryDecodeErc1271Signature_returnsFalseWhen_tooShort() public view {
        _assertRejected(new bytes(0x40), "too-short blob rejected without reverting");
    }

    function test_tryDecodeErc1271Signature_returnsFalseWhen_oneByteShort() public view {
        bytes memory blob = _envelope();
        assembly {
            mstore(blob, sub(mload(blob), 1))
        }
        _assertRejected(blob, "one byte short rejected");
    }

    function test_tryDecodeErc1271Signature_returnsFalseWhen_oneByteLong() public view {
        _assertRejected(abi.encodePacked(_envelope(), bytes1(0xab)), "one byte long rejected");
    }

    function test_tryDecodeErc1271Signature_returnsFalseWhen_wrongMagic() public view {
        bytes memory blob = _envelope();
        blob[3] = 0x54; // "QPCT"
        _assertRejected(blob, "wrong magic rejected");
    }

    function test_tryDecodeErc1271Signature_returnsFalseWhen_wrongVersion() public view {
        bytes memory blob = _envelope();
        blob[Codec.ERC1271_VERSION_OFF] = bytes1(Codec.ERC1271_VERSION + 1);
        _assertRejected(blob, "wrong version rejected");
    }

    function test_tryDecodeErc1271Signature_returnsFalseWhen_wrongProfile() public view {
        bytes memory blob = _envelope();
        blob[Codec.ERC1271_HEADER_LEN - 1] ^= 0x01; // last byte of PROFILE_ID
        _assertRejected(blob, "wrong profile id rejected");
    }

    /// @dev The pre-0.4.0 ABI envelope `abi.encode(PublicKey, Signature, bytes)` is not a valid
    ///      fixed-layout envelope: it fails the length and magic checks.
    function test_tryDecodeErc1271Signature_returnsFalseWhen_legacyAbiEnvelope() public view {
        bytes memory blob =
            abi.encode(_samplePublicKey(), _sampleStatelessSig(), _filled(Codec.ERC1271_ECDSA_LEN, 0xec));
        _assertRejected(blob, "legacy ABI envelope rejected");
    }
}
