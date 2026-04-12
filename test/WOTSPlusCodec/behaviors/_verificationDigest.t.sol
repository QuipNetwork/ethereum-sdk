// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__verificationDigest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant S1 = bytes32(uint256(10));
    bytes32 constant H1 = bytes32(uint256(11));

    function test_exposed_verificationDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.verification");
        address impl = address(0xDEAD);
        bytes32 expected = EfficientHashLib.hash(
            tag, bytes32(C), bytes32(uint256(uint160(W))),
            bytes32(uint256(uint160(impl))), S1, H1
        );
        assertEq(codec.exposed_verificationDigest(W, C, impl, S1, H1), expected);
    }

    function test_exposed_verificationDigest_differsByImplementation() public view {
        bytes32 a = codec.exposed_verificationDigest(W, C, address(0x1), S1, H1);
        bytes32 b = codec.exposed_verificationDigest(W, C, address(0x2), S1, H1);
        assertTrue(a != b);
    }
}
