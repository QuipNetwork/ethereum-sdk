// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodecHarness} from "../../harness/WOTSPlusCodecHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeResetKeyset is WOTSPlusCodecTest {
    function test_exposed_decodeResetKeyset_decodesTxSignTxTarget() public view {
        bytes memory payload = _buildResetKeysetPayload(
            42,
            Codec.KeyType.Transaction,
            Codec.KeyType.Transaction
        );
        assertEq(payload.length, 2976);
        WOTSPlusCodecHarness.DecodedResetKeyset memory out = codec
            .exposed_decodeResetKeyset(payload);

        assertTrue(out.kind == Codec.KeyType.Transaction);
        assertTrue(out.signingKind == Codec.KeyType.Transaction);
        assertEq(out.currentKey.publicSeed, bytes32(uint256(42)));
        assertEq(out.currentKey.publicKeyHash, bytes32(uint256(43)));
        assertEq(out.nextKey.publicSeed, bytes32(uint256(44)));
        assertEq(out.nextKey.publicKeyHash, bytes32(uint256(45)));
        for (uint256 i = 0; i < 10; i++) {
            assertEq(out.newKeys[i].publicSeed, bytes32(42 + 3000 + i * 2));
            assertEq(out.newKeys[i].publicKeyHash, bytes32(42 + 3001 + i * 2));
        }
    }

    function test_exposed_decodeResetKeyset_decodesRecSignVerifyTarget()
        public
        view
    {
        bytes memory payload = _buildResetKeysetPayload(
            7,
            Codec.KeyType.Verification,
            Codec.KeyType.Recovery
        );
        WOTSPlusCodecHarness.DecodedResetKeyset memory out = codec
            .exposed_decodeResetKeyset(payload);

        assertTrue(out.kind == Codec.KeyType.Verification);
        assertTrue(out.signingKind == Codec.KeyType.Recovery);
        for (uint256 i = 0; i < 10; i++) {
            assertEq(out.newKeys[i].publicSeed, bytes32(7 + 3000 + i * 2));
        }
    }

    function test_exposed_decodeResetKeyset_decodesTxSignRecoveryTarget()
        public
        view
    {
        bytes memory payload = _buildResetKeysetPayload(
            99,
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction
        );
        WOTSPlusCodecHarness.DecodedResetKeyset memory out = codec
            .exposed_decodeResetKeyset(payload);

        assertTrue(out.kind == Codec.KeyType.Recovery);
        assertTrue(out.signingKind == Codec.KeyType.Transaction);
    }

    function test_exposed_decodeResetKeyset_revertsWhen_shortPayload() public {
        bytes memory payload = _filledBytes(100);
        vm.expectRevert(
            abi.encodeWithSelector(Codec.MalformedPayload.selector, 2976, 100)
        );
        codec.exposed_decodeResetKeyset(payload);
    }

    function test_exposed_decodeResetKeyset_revertsWhen_oneByteShort() public {
        bytes memory payload = new bytes(2975);
        vm.expectRevert(
            abi.encodeWithSelector(Codec.MalformedPayload.selector, 2976, 2975)
        );
        codec.exposed_decodeResetKeyset(payload);
    }

    function test_exposed_decodeResetKeyset_revertsWhen_oneByteLong() public {
        bytes memory payload = new bytes(2977);
        vm.expectRevert(
            abi.encodeWithSelector(Codec.MalformedPayload.selector, 2976, 2977)
        );
        codec.exposed_decodeResetKeyset(payload);
    }

    function test_exposed_decodeResetKeyset_revertsWhen_garbageSuffix() public {
        bytes memory payload = _buildResetKeysetPayload(
            30,
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction
        );
        payload = abi.encodePacked(payload, bytes32(uint256(0xDEAD)));
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2976,
                payload.length
            )
        );
        codec.exposed_decodeResetKeyset(payload);
    }

    function test_exposed_decodeResetKeyset_revertsWhen_kindOutOfRange()
        public
    {
        bytes memory payload = _buildResetKeysetPayload(
            30,
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction
        );
        // Overwrite kind at byte offset 0 with an out-of-range value.
        assembly {
            mstore(add(payload, 32), 99)
        }
        vm.expectRevert();
        codec.exposed_decodeResetKeyset(payload);
    }

    function test_exposed_decodeResetKeyset_revertsWhen_signingKindOutOfRange()
        public
    {
        bytes memory payload = _buildResetKeysetPayload(
            30,
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction
        );
        // signingKind is at byte offset 32 within payload data.
        assembly {
            mstore(add(payload, 64), 99)
        }
        vm.expectRevert();
        codec.exposed_decodeResetKeyset(payload);
    }

    /// @dev Property: any payload whose length is not exactly 2976 reverts.
    function testFuzz_exposed_decodeResetKeyset_revertsWhen_wrongLength(
        uint256 len
    ) public {
        len = bound(len, 0, 10000);
        vm.assume(len != 2976);
        vm.expectRevert(
            abi.encodeWithSelector(Codec.MalformedPayload.selector, 2976, len)
        );
        codec.exposed_decodeResetKeyset(new bytes(len));
    }
}
