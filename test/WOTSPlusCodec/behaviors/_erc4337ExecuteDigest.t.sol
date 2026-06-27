// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__erc4337ExecuteDigest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant S1 = bytes32(uint256(10));
    bytes32 constant H1 = bytes32(uint256(11));
    bytes32 constant S2 = bytes32(uint256(20));
    bytes32 constant H2 = bytes32(uint256(21));

    function test_exposed_erc4337ExecuteDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.erc4337Execute");
        bytes32 userOpHash = bytes32(uint256(42));
        uint256 fee = 0.01 ether;
        bytes32 expected = EfficientHashLib.hash(
            tag, bytes32(C), bytes32(uint256(uint160(W))), S1, H1, S2, H2, userOpHash, bytes32(fee)
        );
        assertEq(codec.exposed_erc4337ExecuteDigest(W, C, S1, H1, S2, H2, userOpHash, fee), expected);
    }

    function test_exposed_erc4337ExecuteDigest_differsByUserOpHash() public view {
        bytes32 a = codec.exposed_erc4337ExecuteDigest(W, C, S1, H1, S2, H2, bytes32(uint256(1)), 0);
        bytes32 b = codec.exposed_erc4337ExecuteDigest(W, C, S1, H1, S2, H2, bytes32(uint256(2)), 0);
        assertTrue(a != b);
    }

    function test_exposed_erc4337ExecuteDigest_differsByFee() public view {
        bytes32 a = codec.exposed_erc4337ExecuteDigest(W, C, S1, H1, S2, H2, bytes32(uint256(1)), 0);
        bytes32 b = codec.exposed_erc4337ExecuteDigest(W, C, S1, H1, S2, H2, bytes32(uint256(1)), 0.01 ether);
        assertTrue(a != b);
    }
}
