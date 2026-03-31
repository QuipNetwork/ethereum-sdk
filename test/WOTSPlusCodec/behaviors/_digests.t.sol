// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

contract WOTSPlusCodec__digests is WOTSPlusCodecTest {
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

    function test_exposed_executeDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.execute");
        address target = address(0xBEEF);
        uint256 value = 1 ether;
        bytes32 opHash = bytes32(uint256(99));
        bytes32 expected = EfficientHashLib.hash(
            tag, bytes32(C), bytes32(uint256(uint160(W))),
            S1, H1, S2, H2,
            bytes32(uint256(uint160(target))), bytes32(value), opHash
        );
        assertEq(codec.exposed_executeDigest(W, C, S1, H1, S2, H2, target, value, opHash), expected);
    }

    function test_exposed_executeDigest_differsByTargetOrValue() public view {
        bytes32 opHash = bytes32(uint256(99));
        bytes32 a = codec.exposed_executeDigest(W, C, S1, H1, S2, H2, address(0x1), 1 ether, opHash);
        bytes32 b = codec.exposed_executeDigest(W, C, S1, H1, S2, H2, address(0x2), 1 ether, opHash);
        bytes32 c = codec.exposed_executeDigest(W, C, S1, H1, S2, H2, address(0x1), 2 ether, opHash);
        assertTrue(a != b);
        assertTrue(a != c);
    }

    function test_exposed_keyManagementDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.keyManagement");
        bytes32 keysHash = bytes32(uint256(77));
        bytes32 expected = EfficientHashLib.hash(
            tag, bytes32(C), bytes32(uint256(uint160(W))), S1, H1, S2, H2, keysHash
        );
        assertEq(codec.exposed_keyManagementDigest(W, C, S1, H1, S2, H2, keysHash), expected);
    }

    function test_exposed_upgradeDigest_matchesManualHash() public view {
        bytes32 tag = keccak256("quip.digest.upgrade");
        address impl = address(0xDEAD);
        bytes32 expected = EfficientHashLib.hash(
            tag, bytes32(C), bytes32(uint256(uint160(W))),
            bytes32(uint256(uint160(impl))), S1, H1, S2, H2
        );
        assertEq(codec.exposed_upgradeDigest(W, C, impl, S1, H1, S2, H2), expected);
    }

    function test_exposed_upgradeDigest_differsByImplementation() public view {
        bytes32 a = codec.exposed_upgradeDigest(W, C, address(0x1), S1, H1, S2, H2);
        bytes32 b = codec.exposed_upgradeDigest(W, C, address(0x2), S1, H1, S2, H2);
        assertTrue(a != b);
    }

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

    function test_exposed_digestsUseDifferentDomainTags() public view {
        // keyRotation and keyManagement share (wallet, chainId, s1, h1, s2, h2) params
        // but should produce different digests
        bytes32 kr = codec.exposed_keyRotationDigest(W, C, S1, H1, S2, H2);
        bytes32 km = codec.exposed_keyManagementDigest(W, C, S1, H1, S2, H2, bytes32(0));
        assertTrue(kr != km);
    }
}
