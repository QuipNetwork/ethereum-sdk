// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__executeDigest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant S1 = bytes32(uint256(10));
    bytes32 constant H1 = bytes32(uint256(11));
    bytes32 constant S2 = bytes32(uint256(20));
    bytes32 constant H2 = bytes32(uint256(21));

    function test_exposed_executeDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.execute");
        address target = address(0xBEEF);
        uint256 value = 1 ether;
        bytes32 opHash = bytes32(uint256(99));
        uint256 fee = 0.01 ether;
        bytes32 expected = EfficientHashLib.hash(
            tag,
            bytes32(C),
            bytes32(uint256(uint160(W))),
            S1,
            H1,
            S2,
            H2,
            bytes32(uint256(uint160(target))),
            bytes32(value),
            opHash,
            bytes32(fee)
        );
        assertEq(
            codec.exposed_executeDigest(
                W,
                C,
                S1,
                H1,
                S2,
                H2,
                target,
                value,
                opHash,
                fee
            ),
            expected
        );
    }

    function test_exposed_executeDigest_differsByTargetOrValue() public view {
        bytes32 opHash = bytes32(uint256(99));
        bytes32 a = codec.exposed_executeDigest(
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            address(0x1),
            1 ether,
            opHash,
            0
        );
        bytes32 b = codec.exposed_executeDigest(
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            address(0x2),
            1 ether,
            opHash,
            0
        );
        bytes32 c = codec.exposed_executeDigest(
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            address(0x1),
            2 ether,
            opHash,
            0
        );
        assertTrue(a != b);
        assertTrue(a != c);
    }

    function test_exposed_executeDigest_differsByFee() public view {
        bytes32 opHash = bytes32(uint256(99));
        bytes32 a = codec.exposed_executeDigest(
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            address(0x1),
            1 ether,
            opHash,
            0
        );
        bytes32 b = codec.exposed_executeDigest(
            W,
            C,
            S1,
            H1,
            S2,
            H2,
            address(0x1),
            1 ether,
            opHash,
            0.01 ether
        );
        assertTrue(a != b);
    }
}
