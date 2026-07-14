// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__transferOwnershipDigest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant S1 = bytes32(uint256(10));
    bytes32 constant H1 = bytes32(uint256(11));
    bytes32 constant S2 = bytes32(uint256(20));
    bytes32 constant H2 = bytes32(uint256(21));
    bytes32 constant KEYS_HASH = bytes32(uint256(0xABCDEF));

    function test_exposed_transferOwnershipDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.transferOwnership");
        address newOwner = address(0xBEEF);
        bytes32 expected = EfficientHashLib.hash(
            tag,
            bytes32(C),
            bytes32(uint256(uint160(W))),
            S1,
            H1,
            S2,
            H2,
            bytes32(uint256(uint160(newOwner))),
            KEYS_HASH
        );
        assertEq(codec.exposed_transferOwnershipDigest(W, C, S1, H1, S2, H2, newOwner, KEYS_HASH), expected);
    }

    function test_exposed_transferOwnershipDigest_differsByNewOwner() public view {
        bytes32 a = codec.exposed_transferOwnershipDigest(W, C, S1, H1, S2, H2, address(0x1), KEYS_HASH);
        bytes32 b = codec.exposed_transferOwnershipDigest(W, C, S1, H1, S2, H2, address(0x2), KEYS_HASH);
        assertTrue(a != b);
    }

    function test_exposed_transferOwnershipDigest_differsByWallet() public view {
        bytes32 a = codec.exposed_transferOwnershipDigest(address(0x1), C, S1, H1, S2, H2, address(0xBEEF), KEYS_HASH);
        bytes32 b = codec.exposed_transferOwnershipDigest(address(0x2), C, S1, H1, S2, H2, address(0xBEEF), KEYS_HASH);
        assertTrue(a != b);
    }

    function test_exposed_transferOwnershipDigest_differsByChainId() public view {
        bytes32 a = codec.exposed_transferOwnershipDigest(W, 1, S1, H1, S2, H2, address(0xBEEF), KEYS_HASH);
        bytes32 b = codec.exposed_transferOwnershipDigest(W, 2, S1, H1, S2, H2, address(0xBEEF), KEYS_HASH);
        assertTrue(a != b);
    }

    function test_exposed_transferOwnershipDigest_differsByKeysHash() public view {
        bytes32 a =
            codec.exposed_transferOwnershipDigest(W, C, S1, H1, S2, H2, address(0xBEEF), bytes32(uint256(0x111)));
        bytes32 b =
            codec.exposed_transferOwnershipDigest(W, C, S1, H1, S2, H2, address(0xBEEF), bytes32(uint256(0x222)));
        assertTrue(a != b);
    }
}
