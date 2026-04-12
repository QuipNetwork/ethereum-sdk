// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__keyRotationDigest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant S1 = bytes32(uint256(10));
    bytes32 constant H1 = bytes32(uint256(11));
    bytes32 constant S2 = bytes32(uint256(20));
    bytes32 constant H2 = bytes32(uint256(21));

    function test_exposed_keyRotationDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.keyRotation");
        bytes32 expected = EfficientHashLib.hash(tag, bytes32(C), bytes32(uint256(uint160(W))), S1, H1, S2, H2);
        assertEq(codec.exposed_keyRotationDigest(W, C, S1, H1, S2, H2), expected);
    }

    function test_exposed_keyRotationDigest_differsByChainId() public view {
        bytes32 a = codec.exposed_keyRotationDigest(W, 1, S1, H1, S2, H2);
        bytes32 b = codec.exposed_keyRotationDigest(W, 2, S1, H1, S2, H2);
        assertTrue(a != b);
    }

    function test_exposed_keyRotationDigest_differsByWallet() public view {
        bytes32 a = codec.exposed_keyRotationDigest(address(0x1), C, S1, H1, S2, H2);
        bytes32 b = codec.exposed_keyRotationDigest(address(0x2), C, S1, H1, S2, H2);
        assertTrue(a != b);
    }

    function test_exposed_keyRotationDigest_differFromKeyManagementDigest() public view {
        bytes32 kr = codec.exposed_keyRotationDigest(W, C, S1, H1, S2, H2);
        bytes32 km = codec.exposed_keyManagementDigest(W, C, S1, H1, S2, H2, bytes32(0));
        assertTrue(kr != km);
    }
}
