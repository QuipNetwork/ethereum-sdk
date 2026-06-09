// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__upgradeRecoveryDigest is WOTSPlusCodecTest {
    address constant W = address(0xAAAA);
    uint256 constant C = 1;
    bytes32 constant RS1 = bytes32(uint256(30));
    bytes32 constant RH1 = bytes32(uint256(31));
    bytes32 constant RS2 = bytes32(uint256(32));
    bytes32 constant RH2 = bytes32(uint256(33));
    bytes32 constant S1 = bytes32(uint256(10));
    bytes32 constant H1 = bytes32(uint256(11));
    bytes32 constant S2 = bytes32(uint256(20));
    bytes32 constant H2 = bytes32(uint256(21));

    function test_exposed_upgradeRecoveryDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.upgradeRecovery");
        address impl = address(0xDEAD);
        bytes32 expected = EfficientHashLib.hash(
            tag, bytes32(C), bytes32(uint256(uint160(W))), bytes32(uint256(uint160(impl))), RS1, RH1, RS2, RH2
        );
        assertEq(codec.exposed_upgradeRecoveryDigest(W, C, impl, RS1, RH1, RS2, RH2), expected);
    }

    function test_exposed_upgradeRecoveryDigest_differsByImplementation() public view {
        bytes32 a = codec.exposed_upgradeRecoveryDigest(W, C, address(0x1), RS1, RH1, RS2, RH2);
        bytes32 b = codec.exposed_upgradeRecoveryDigest(W, C, address(0x2), RS1, RH1, RS2, RH2);
        assertTrue(a != b);
    }

    function test_exposed_upgradeRecoveryDigest_differsByNewRecoveryKey() public view {
        bytes32 a = codec.exposed_upgradeRecoveryDigest(W, C, address(0xDEAD), RS1, RH1, RS2, RH2);
        bytes32 b = codec.exposed_upgradeRecoveryDigest(
            W, C, address(0xDEAD), RS1, RH1, bytes32(uint256(99)), bytes32(uint256(100))
        );
        assertTrue(a != b);
    }

    function test_exposed_upgradeRecoveryDigest_differsByNewRecoveryKey()
        public
        view
    {
        bytes32 a = codec.exposed_upgradeRecoveryDigest(
            W,
            C,
            address(0xDEAD),
            RS1,
            RH1,
            RS2,
            RH2
        );
        bytes32 b = codec.exposed_upgradeRecoveryDigest(
            W,
            C,
            address(0xDEAD),
            RS1,
            RH1,
            bytes32(uint256(99)),
            bytes32(uint256(100))
        );
        assertTrue(a != b);
    }

    function test_exposed_upgradeRecoveryDigest_differsFromUpgradeDigest()
        public
        view
    {
        bytes32 a = codec.exposed_upgradeRecoveryDigest(
            W,
            C,
            address(0xDEAD),
            RS1,
            RH1,
            RS2,
            RH2
        );
        bytes32 b = codec.exposed_upgradeDigest(
            W,
            C,
            address(0xDEAD),
            S1,
            H1,
            S2,
            H2,
            false,
            keccak256(new bytes(2048))
        );
        assertTrue(a != b);
    }
}
