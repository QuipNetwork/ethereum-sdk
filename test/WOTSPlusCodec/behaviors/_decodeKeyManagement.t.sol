// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeKeyManagement is WOTSPlusCodecTest {
    function test_exposed_decodeKeyManagement_decodesWithMultipleKeys()
        public
        view
    {
        bytes memory payload = _buildKeyManagementPayload(
            30,
            3,
            Codec.KeyType.Recovery
        );
        (
            Codec.KeyType kind,
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            ,
            WOTSPlus.WinternitzAddress[] memory keys
        ) = codec.exposed_decodeKeyManagement(payload);

        assertTrue(kind == Codec.KeyType.Recovery);
        assertEq(cur.publicSeed, bytes32(uint256(30)));
        assertEq(cur.publicKeyHash, bytes32(uint256(31)));
        assertEq(nxt.publicSeed, bytes32(uint256(32)));
        assertEq(nxt.publicKeyHash, bytes32(uint256(33)));
        assertEq(keys.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertEq(keys[i].publicSeed, bytes32(uint256(30 + 500 + i * 2)));
            assertEq(keys[i].publicKeyHash, bytes32(uint256(30 + 501 + i * 2)));
        }
    }

    function test_exposed_decodeKeyManagement_decodesWithZeroKeys()
        public
        view
    {
        bytes memory payload = _buildKeyManagementPayload(
            30,
            0,
            Codec.KeyType.Verification
        );
        (
            Codec.KeyType kind,
            ,
            ,
            ,
            WOTSPlus.WinternitzAddress[] memory keys
        ) = codec.exposed_decodeKeyManagement(payload);
        assertTrue(kind == Codec.KeyType.Verification);
        assertEq(keys.length, 0);
    }

    function test_exposed_decodeKeyManagement_decodesWithMaxKeys() public view {
        bytes memory payload = _buildKeyManagementPayload(
            30,
            10,
            Codec.KeyType.Transaction
        );
        (
            Codec.KeyType kind,
            ,
            ,
            ,
            WOTSPlus.WinternitzAddress[] memory keys
        ) = codec.exposed_decodeKeyManagement(payload);
        assertTrue(kind == Codec.KeyType.Transaction);
        assertEq(keys.length, 10);
    }

    function test_exposed_decodeKeyManagement_revertsWhen_shortPayload()
        public
    {
        bytes memory payload = _filledBytes(100);
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2304,
                100
            )
        );
        codec.exposed_decodeKeyManagement(payload);
    }

    function test_exposed_decodeKeyManagement_exactMinLength_succeeds()
        public
        view
    {
        // 2304 bytes: leading 32-byte kind (=0, Transaction) + currentKey(64)
        // + nextKey(64) + pqSig(2144). No trailing keys.
        bytes memory payload = new bytes(2304);
        (
            ,
            ,
            ,
            ,
            WOTSPlus.WinternitzAddress[] memory keys
        ) = codec.exposed_decodeKeyManagement(payload);
        assertEq(keys.length, 0);
    }

    function test_exposed_decodeKeyManagement_revertsWhen_kindOutOfRange()
        public
    {
        // A filled 2304-byte payload has a leading 0xAB…AB kind value far out of
        // the KeyType enum range; the implicit enum cast must revert.
        bytes memory payload = _filledBytes(2304);
        vm.expectRevert();
        codec.exposed_decodeKeyManagement(payload);
    }

    function test_exposed_decodeKeyManagement_revertsWhen_unalignedLength()
        public
    {
        // 2336 bytes: 2304 baseline + 32 trailing bytes (not a full 64-byte key).
        // Pre-fix: integer division silently floored trailing-key length to 0.
        // Post-fix: alignment is contractually enforced.
        bytes memory payload = new bytes(2336);
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2304,
                2336
            )
        );
        codec.exposed_decodeKeyManagement(payload);
    }

    // Direct check on the bug the strict length check fixes: a payload short
    // by even one byte used to make `keys.length := div(sub(2303, 2304), 64)`
    // wrap to ~2^250 in Yul, turning any keys-iterating caller into a gas bomb.
    function test_exposed_decodeKeyManagement_revertsWhen_oneByteShort_blocksUnderflow()
        public
    {
        bytes memory payload = new bytes(2303);
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2304,
                2303
            )
        );
        codec.exposed_decodeKeyManagement(payload);
    }

    /// @dev Property: any payload shorter than the 2304-byte header reverts.
    ///      Uses `new bytes(len)` (zero-filled) so the leading 32-byte `kind`
    ///      cast doesn't fire ahead of the length check.
    function testFuzz_exposed_decodeKeyManagement_revertsWhen_short(
        uint256 len
    ) public {
        len = bound(len, 0, 2303);
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2304,
                len
            )
        );
        codec.exposed_decodeKeyManagement(new bytes(len));
    }

    /// @dev Property: a payload of length >= 2304 with a tail that's not a
    ///      multiple of 64 bytes reverts. This is the alignment branch of the
    ///      length precondition that prevents the trailing-keys array length
    ///      from underflowing in Yul.
    function testFuzz_exposed_decodeKeyManagement_revertsWhen_unalignedLength(
        uint256 len
    ) public {
        len = bound(len, 2304, 5000);
        vm.assume((len - 2304) % 64 != 0);
        vm.expectRevert(
            abi.encodeWithSelector(
                Codec.MalformedPayload.selector,
                2304,
                len
            )
        );
        codec.exposed_decodeKeyManagement(new bytes(len));
    }
}
