// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__erc1271Digest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant VSEED = bytes32(uint256(10));
    bytes32 constant VHASH = bytes32(uint256(11));
    bytes32 constant MSG = bytes32(uint256(0xBEEF));

    function test_exposed_erc1271Digest_matchesManualHash() public view {
        bytes32 expected = EfficientHashLib.hash(
            keccak256("quip.digest.erc1271"),
            bytes32(C),
            bytes32(uint256(uint160(W))),
            VSEED,
            VHASH,
            MSG
        );
        assertEq(
            codec.exposed_erc1271Digest(W, C, VSEED, VHASH, MSG),
            expected
        );
    }

    function test_exposed_erc1271Digest_differsByWallet() public view {
        bytes32 a = codec.exposed_erc1271Digest(
            address(0x1),
            C,
            VSEED,
            VHASH,
            MSG
        );
        bytes32 b = codec.exposed_erc1271Digest(
            address(0x2),
            C,
            VSEED,
            VHASH,
            MSG
        );
        assertTrue(a != b);
    }

    function test_exposed_erc1271Digest_differsByChainId() public view {
        bytes32 a = codec.exposed_erc1271Digest(W, 1, VSEED, VHASH, MSG);
        bytes32 b = codec.exposed_erc1271Digest(W, 2, VSEED, VHASH, MSG);
        assertTrue(a != b);
    }

    function test_exposed_erc1271Digest_differsByVerifier() public view {
        bytes32 a = codec.exposed_erc1271Digest(
            W,
            C,
            bytes32(uint256(0x111)),
            VHASH,
            MSG
        );
        bytes32 b = codec.exposed_erc1271Digest(
            W,
            C,
            bytes32(uint256(0x222)),
            VHASH,
            MSG
        );
        assertTrue(a != b);
    }

    function test_exposed_erc1271Digest_differsByMessage() public view {
        bytes32 a = codec.exposed_erc1271Digest(
            W,
            C,
            VSEED,
            VHASH,
            bytes32(uint256(0x111))
        );
        bytes32 b = codec.exposed_erc1271Digest(
            W,
            C,
            VSEED,
            VHASH,
            bytes32(uint256(0x222))
        );
        assertTrue(a != b);
    }
}
