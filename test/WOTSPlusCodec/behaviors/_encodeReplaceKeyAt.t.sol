// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeReplaceKeyAt is WOTSPlusCodecTest {
    function test_exposed_encodeReplaceKeyAt_producesCorrectLength()
        public
        view
    {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        WOTSPlus.WinternitzAddress memory newKey = WOTSPlus.WinternitzAddress(
            bytes32(uint256(5)),
            bytes32(uint256(6))
        );

        bytes memory encoded = codec.exposed_encodeReplaceKeyAt(
            Codec.KeyType.Transaction,
            cur,
            nxt,
            sig,
            7,
            newKey
        );
        // 32 (kind) + 64 (cur) + 64 (nxt) + 2144 (sig) + 32 (index) + 64 (newKey) = 2400
        assertEq(encoded.length, 2400);
    }

    function test_exposed_encodeReplaceKeyAt_roundtrips() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        WOTSPlus.WinternitzElements memory sig;
        for (uint256 i = 0; i < 67; i++) sig.elements[i] = bytes32(i + 200);
        WOTSPlus.WinternitzAddress memory newKey = WOTSPlus.WinternitzAddress(
            bytes32(uint256(500)),
            bytes32(uint256(501))
        );

        bytes memory encoded = codec.exposed_encodeReplaceKeyAt(
            Codec.KeyType.Verification,
            cur,
            nxt,
            sig,
            3,
            newKey
        );
        (
            Codec.KeyType kind,
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            uint256 dIdx,
            WOTSPlus.WinternitzAddress memory dNewKey
        ) = codec.exposed_decodeReplaceKeyAt(encoded);

        assertTrue(kind == Codec.KeyType.Verification);
        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dIdx, 3);
        assertEq(dNewKey.publicSeed, newKey.publicSeed);
        assertEq(dNewKey.publicKeyHash, newKey.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
    }

    function test_exposed_encodeReplaceKeyAt_recoveryKind_roundtrips()
        public
        view
    {
        WOTSPlus.WinternitzAddress memory zero;
        WOTSPlus.WinternitzElements memory sig;
        bytes memory encoded = codec.exposed_encodeReplaceKeyAt(
            Codec.KeyType.Recovery,
            zero,
            zero,
            sig,
            9,
            zero
        );
        (Codec.KeyType kind, , , , uint256 dIdx, ) = codec
            .exposed_decodeReplaceKeyAt(encoded);
        assertTrue(kind == Codec.KeyType.Recovery);
        assertEq(dIdx, 9);
    }

    /// @dev Property: encode → decode preserves every field for any inputs.
    ///      Pins the 2400-byte replaceKeyAt layout: 32-byte left-padded `kind`
    ///      header, 32-byte left-padded `index` between sig and newKey.
    function testFuzz_exposed_encodeReplaceKeyAt_roundtrips(
        bytes32 seed,
        uint8 kindRaw,
        uint256 index
    ) public view {
        Codec.KeyType kind = Codec.KeyType(kindRaw % 3);
        WOTSPlus.WinternitzAddress memory cur = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory nxt = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzElements memory sig = _fuzzWinternitzElements(seed);
        WOTSPlus.WinternitzAddress memory newKey = _fuzzWinternitzAddress(seed, 2);

        bytes memory encoded = codec.exposed_encodeReplaceKeyAt(
            kind,
            cur,
            nxt,
            sig,
            index,
            newKey
        );
        assertEq(encoded.length, 2400);

        (
            Codec.KeyType dKind,
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            uint256 dIdx,
            WOTSPlus.WinternitzAddress memory dNewKey
        ) = codec.exposed_decodeReplaceKeyAt(encoded);

        assertTrue(dKind == kind);
        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dCur.publicKeyHash, cur.publicKeyHash);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
        assertEq(dIdx, index);
        assertEq(dNewKey.publicSeed, newKey.publicSeed);
        assertEq(dNewKey.publicKeyHash, newKey.publicKeyHash);
    }
}
