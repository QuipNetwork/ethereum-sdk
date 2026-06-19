// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeErc1271Signature is WOTSPlusCodecTest {
    function test_exposed_encodeErc1271Signature_producesCorrectLength() public view {
        WOTSPlus.WinternitzAddress memory verifier =
            WOTSPlus.WinternitzAddress(bytes32(uint256(1)), bytes32(uint256(2)));
        WOTSPlus.WinternitzElements memory sig;
        bytes memory ecdsa = new bytes(65);
        bytes memory encoded = codec.exposed_encodeErc1271Signature(verifier, sig, ecdsa);
        assertEq(encoded.length, 2273);
    }

    function test_exposed_encodeErc1271Signature_roundtrips() public view {
        WOTSPlus.WinternitzAddress memory verifier =
            WOTSPlus.WinternitzAddress(bytes32(uint256(10)), bytes32(uint256(11)));
        WOTSPlus.WinternitzElements memory sig;
        for (uint256 i = 0; i < 67; i++) {
            sig.elements[i] = bytes32(i + 500);
        }
        bytes memory ecdsa = abi.encodePacked(bytes32(uint256(0xAAAA)), bytes32(uint256(0xBBBB)), uint8(28));

        bytes memory encoded = codec.exposed_encodeErc1271Signature(verifier, sig, ecdsa);
        (WOTSPlus.WinternitzAddress memory dVerifier, WOTSPlus.WinternitzElements memory dSig, bytes memory dEcdsa) =
            codec.exposed_decodeErc1271Signature(encoded);

        assertEq(dVerifier.publicSeed, verifier.publicSeed);
        assertEq(dVerifier.publicKeyHash, verifier.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
        assertEq(dEcdsa.length, 65);
        assertEq(dEcdsa, ecdsa);
    }

    /// @dev Property: encode → decode preserves every field for any seed.
    ///      Pins the 2273-byte ERC-1271 signature layout — note the 65-byte
    ///      `ecdsaSig` tail is the only odd-aligned field in the codec.
    function testFuzz_exposed_encodeErc1271Signature_roundtrips(bytes32 seed) public view {
        WOTSPlus.WinternitzAddress memory verifier = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzElements memory sig = _fuzzWinternitzElements(seed);
        bytes memory ecdsa = _fuzzEcdsaSignature(seed);

        bytes memory encoded = codec.exposed_encodeErc1271Signature(verifier, sig, ecdsa);
        assertEq(encoded.length, 2273);

        (WOTSPlus.WinternitzAddress memory dVerifier, WOTSPlus.WinternitzElements memory dSig, bytes memory dEcdsa) =
            codec.exposed_decodeErc1271Signature(encoded);

        assertEq(dVerifier.publicSeed, verifier.publicSeed);
        assertEq(dVerifier.publicKeyHash, verifier.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
        assertEq(dEcdsa.length, 65);
        assertEq(dEcdsa, ecdsa);
    }
}
