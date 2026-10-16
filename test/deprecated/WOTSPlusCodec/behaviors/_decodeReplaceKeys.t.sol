// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodecHarness} from "../../harness/WOTSPlusCodecHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeReplaceKeys is WOTSPlusCodecTest {
    function test_exposed_decodeReplaceKeys_decodesN1() public view {
        bytes memory payload = _buildReplaceKeysPayload(30, 1, Codec.KeyType.Recovery, Codec.KeyType.Transaction);
        WOTSPlusCodecHarness.DecodedReplaceKeys memory out = codec.exposed_decodeReplaceKeys(payload);

        assertTrue(out.kind == Codec.KeyType.Recovery);
        assertTrue(out.signingKind == Codec.KeyType.Transaction);
        assertEq(out.n, 1);
        assertEq(out.currentKey.publicSeed, bytes32(uint256(30)));
        assertEq(out.currentKey.publicKeyHash, bytes32(uint256(31)));
        assertEq(out.nextKey.publicSeed, bytes32(uint256(32)));
        assertEq(out.nextKey.publicKeyHash, bytes32(uint256(33)));
        assertEq(out.oldKeys.length, 1);
        assertEq(out.newKeys.length, 1);
        assertEq(out.oldKeys[0].publicSeed, bytes32(uint256(1030)));
        assertEq(out.oldKeys[0].publicKeyHash, bytes32(uint256(1031)));
        assertEq(out.newKeys[0].publicSeed, bytes32(uint256(2030)));
        assertEq(out.newKeys[0].publicKeyHash, bytes32(uint256(2031)));
    }

    function test_exposed_decodeReplaceKeys_decodesN5() public view {
        bytes memory payload = _buildReplaceKeysPayload(42, 5, Codec.KeyType.Transaction, Codec.KeyType.Recovery);
        WOTSPlusCodecHarness.DecodedReplaceKeys memory out = codec.exposed_decodeReplaceKeys(payload);

        assertTrue(out.kind == Codec.KeyType.Transaction);
        assertTrue(out.signingKind == Codec.KeyType.Recovery);
        assertEq(out.n, 5);
        assertEq(out.oldKeys.length, 5);
        assertEq(out.newKeys.length, 5);
        for (uint256 i = 0; i < 5; i++) {
            assertEq(out.oldKeys[i].publicSeed, bytes32(42 + 1000 + i * 2));
            assertEq(out.oldKeys[i].publicKeyHash, bytes32(42 + 1001 + i * 2));
            assertEq(out.newKeys[i].publicSeed, bytes32(42 + 2000 + i * 2));
            assertEq(out.newKeys[i].publicKeyHash, bytes32(42 + 2001 + i * 2));
        }
    }

    function test_exposed_decodeReplaceKeys_decodesN10() public view {
        bytes memory payload = _buildReplaceKeysPayload(7, 10, Codec.KeyType.Verification, Codec.KeyType.Transaction);
        WOTSPlusCodecHarness.DecodedReplaceKeys memory out = codec.exposed_decodeReplaceKeys(payload);

        assertTrue(out.kind == Codec.KeyType.Verification);
        assertTrue(out.signingKind == Codec.KeyType.Transaction);
        assertEq(out.n, 10);
        assertEq(out.oldKeys.length, 10);
        assertEq(out.newKeys.length, 10);
    }

    function test_exposed_decodeReplaceKeys_decodesN0() public view {
        // Zero-N payloads are decodable at the codec layer (HEADER = 2368
        // bytes with no trailing keys). The wallet's `replaceKeys` rejects
        // them with `EmptyKeys`, but that's a higher-layer policy.
        bytes memory payload = _buildReplaceKeysPayload(99, 0, Codec.KeyType.Transaction, Codec.KeyType.Recovery);
        assertEq(payload.length, 2368);
        WOTSPlusCodecHarness.DecodedReplaceKeys memory out = codec.exposed_decodeReplaceKeys(payload);

        assertEq(out.n, 0);
        assertEq(out.oldKeys.length, 0);
        assertEq(out.newKeys.length, 0);
    }

    function test_exposed_decodeReplaceKeys_revertsWhen_shortPayload() public {
        bytes memory payload = _filledBytes(100);
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 2368, 100));
        codec.exposed_decodeReplaceKeys(payload);
    }

    function test_exposed_decodeReplaceKeys_revertsWhen_oneByteShort() public {
        bytes memory payload = new bytes(2367);
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 2368, 2367));
        codec.exposed_decodeReplaceKeys(payload);
    }

    function test_exposed_decodeReplaceKeys_revertsWhen_lengthMismatch_nTooLarge() public {
        // Build an N=2 payload but stuff n=3 into the header — the decoder's
        // expectedLen check (2368 + 2*3*64 = 2752) will not match the actual
        // 2368 + 2*2*64 = 2624 byte length.
        bytes memory payload = _buildReplaceKeysPayload(30, 2, Codec.KeyType.Recovery, Codec.KeyType.Transaction);
        // Overwrite the n field (offset 64) with 3.
        assembly {
            // payload is bytes memory; first 32 bytes is its length, then data.
            // Data offset 64 = memory offset (payload + 32 + 64) = payload + 96.
            mstore(add(payload, 96), 3)
        }
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 2368 + 2 * 3 * 64, payload.length));
        codec.exposed_decodeReplaceKeys(payload);
    }

    function test_exposed_decodeReplaceKeys_revertsWhen_lengthMismatch_nTooSmall() public {
        // Build an N=3 payload but stuff n=2 — expectedLen mismatches.
        bytes memory payload = _buildReplaceKeysPayload(30, 3, Codec.KeyType.Recovery, Codec.KeyType.Transaction);
        assembly {
            mstore(add(payload, 96), 2)
        }
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 2368 + 2 * 2 * 64, payload.length));
        codec.exposed_decodeReplaceKeys(payload);
    }

    function test_exposed_decodeReplaceKeys_revertsWhen_garbageSuffix() public {
        // Build a clean N=1 payload then append 32 bytes — length no longer
        // matches expected.
        bytes memory payload = _buildReplaceKeysPayload(30, 1, Codec.KeyType.Recovery, Codec.KeyType.Transaction);
        payload = abi.encodePacked(payload, bytes32(uint256(0xDEAD)));
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 2368 + 2 * 1 * 64, payload.length));
        codec.exposed_decodeReplaceKeys(payload);
    }

    function test_exposed_decodeReplaceKeys_revertsWhen_kindOutOfRange() public {
        // Build a clean N=1 payload then overwrite the kind field (offset 0)
        // with an out-of-range value. The enum cast in the decoder must revert.
        bytes memory payload = _buildReplaceKeysPayload(30, 1, Codec.KeyType.Recovery, Codec.KeyType.Transaction);
        assembly {
            mstore(add(payload, 32), 99)
        }
        vm.expectRevert();
        codec.exposed_decodeReplaceKeys(payload);
    }

    function test_exposed_decodeReplaceKeys_revertsWhen_signingKindOutOfRange() public {
        bytes memory payload = _buildReplaceKeysPayload(30, 1, Codec.KeyType.Recovery, Codec.KeyType.Transaction);
        assembly {
            // signingKind is at byte offset 32 within payload data.
            mstore(add(payload, 64), 99)
        }
        vm.expectRevert();
        codec.exposed_decodeReplaceKeys(payload);
    }

    /// @dev Property: any payload shorter than 2368 bytes reverts.
    function testFuzz_exposed_decodeReplaceKeys_revertsWhen_short(uint256 len) public {
        len = bound(len, 0, 2367);
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 2368, len));
        codec.exposed_decodeReplaceKeys(new bytes(len));
    }

    /// @dev Property: payloads at or above 2368 bytes whose length does not
    ///      equal 2368 + 2*n*64 (for the n read at byte offset 64) revert.
    function testFuzz_exposed_decodeReplaceKeys_revertsWhen_lengthMismatch(uint256 len) public {
        // n is read from the zero-filled `new bytes(len)`, so n=0 → expected
        // length 2368. We pick payloads >= 2368 but != 2368 so the mismatch
        // fires.
        len = bound(len, 2369, 10000);
        vm.expectRevert(abi.encodeWithSelector(Codec.MalformedPayload.selector, 2368, len));
        codec.exposed_decodeReplaceKeys(new bytes(len));
    }
}
