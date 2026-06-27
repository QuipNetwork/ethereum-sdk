// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeKeyManagement is WOTSPlusCodecTest {
    function test_exposed_encodeKeyManagement_producesCorrectLength()
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
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys[i] = WOTSPlus.WinternitzAddress(
                bytes32(i + 10),
                bytes32(i + 20)
            );
        }
        bytes memory encoded = codec.exposed_encodeKeyManagement(
            Codec.KeyType.Recovery,
            cur,
            nxt,
            sig,
            keys
        );
        // 32 (kind) + 64 (cur) + 64 (nxt) + 2144 (sig) + 3 * 64
        assertEq(encoded.length, 32 + 64 + 64 + 2144 + 3 * 64);
    }

    function test_exposed_encodeKeyManagement_roundtrips() public view {
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
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            keys[i] = WOTSPlus.WinternitzAddress(
                bytes32(i + 10),
                bytes32(i + 20)
            );
        }

        bytes memory encoded = codec.exposed_encodeKeyManagement(
            Codec.KeyType.Verification,
            cur,
            nxt,
            sig,
            keys
        );
        (
            Codec.KeyType kind,
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            ,
            WOTSPlus.WinternitzAddress[] memory dKeys
        ) = codec.exposed_decodeKeyManagement(encoded);

        assertTrue(kind == Codec.KeyType.Verification);
        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dKeys.length, 3);
        for (uint256 i = 0; i < 3; i++) {
            assertEq(dKeys[i].publicSeed, keys[i].publicSeed);
            assertEq(dKeys[i].publicKeyHash, keys[i].publicKeyHash);
        }
    }

    function test_exposed_encodeKeyManagement_roundtripsEmptyKeys()
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
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](0);
        bytes memory encoded = codec.exposed_encodeKeyManagement(
            Codec.KeyType.Transaction,
            cur,
            nxt,
            sig,
            keys
        );
        assertEq(encoded.length, 32 + 64 + 64 + 2144);
        (
            Codec.KeyType kind,
            ,
            ,
            ,
            WOTSPlus.WinternitzAddress[] memory dKeys
        ) = codec.exposed_decodeKeyManagement(encoded);
        assertTrue(kind == Codec.KeyType.Transaction);
        assertEq(dKeys.length, 0);
    }

    /// @dev Property: encode → decode preserves every field for any seed,
    ///      key count, and KeyType. Catches offset drift across the
    ///      variable-length 2304+N*64 keyManagement layout, including the
    ///      32-byte left-padded `kind` prefix that's load-then-cast.
    function testFuzz_exposed_encodeKeyManagement_roundtrips(
        bytes32 seed,
        uint8 kindRaw,
        uint8 numKeys
    ) public view {
        Codec.KeyType kind = Codec.KeyType(kindRaw % 3);
        uint256 n = numKeys % 21; // bound to [0, 20] to keep fuzz fast
        WOTSPlus.WinternitzAddress memory cur = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory nxt = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzElements memory sig = _fuzzWinternitzElements(seed);
        WOTSPlus.WinternitzAddress[] memory keys = _fuzzWinternitzAddressArray(seed, n);

        bytes memory encoded = codec.exposed_encodeKeyManagement(
            kind,
            cur,
            nxt,
            sig,
            keys
        );
        assertEq(encoded.length, 32 + 64 + 64 + 2144 + n * 64);

        (
            Codec.KeyType dKind,
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            WOTSPlus.WinternitzAddress[] memory dKeys
        ) = codec.exposed_decodeKeyManagement(encoded);

        assertTrue(dKind == kind);
        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dCur.publicKeyHash, cur.publicKeyHash);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
        assertEq(dKeys.length, n);
        for (uint256 i = 0; i < n; i++) {
            assertEq(dKeys[i].publicSeed, keys[i].publicSeed);
            assertEq(dKeys[i].publicKeyHash, keys[i].publicKeyHash);
        }
    }
}
