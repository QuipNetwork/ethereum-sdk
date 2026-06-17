// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodecHarness} from "../../harness/WOTSPlusCodecHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeReplaceKeys is WOTSPlusCodecTest {
    function test_exposed_encodeReplaceKeys_producesCorrectLength_N3()
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
            memory oldKeys = new WOTSPlus.WinternitzAddress[](3);
        WOTSPlus.WinternitzAddress[]
            memory newKeys = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            oldKeys[i] = WOTSPlus.WinternitzAddress(
                bytes32(10 + i * 2),
                bytes32(11 + i * 2)
            );
            newKeys[i] = WOTSPlus.WinternitzAddress(
                bytes32(100 + i * 2),
                bytes32(101 + i * 2)
            );
        }
        bytes memory encoded = codec.exposed_encodeReplaceKeys(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            3,
            cur,
            nxt,
            sig,
            oldKeys,
            newKeys
        );
        // 32 (kind) + 32 (signingKind) + 32 (n) + 64 (cur) + 64 (nxt) +
        // 2144 (sig) + 2 * 3 * 64 (arrays) = 2368 + 384 = 2752
        assertEq(encoded.length, 2368 + 2 * 3 * 64);
    }

    function test_exposed_encodeReplaceKeys_roundtrips_N1() public view {
        _assertRoundtrip(Codec.KeyType.Transaction, Codec.KeyType.Recovery, 1);
    }

    function test_exposed_encodeReplaceKeys_roundtrips_N5() public view {
        _assertRoundtrip(Codec.KeyType.Verification, Codec.KeyType.Transaction, 5);
    }

    function test_exposed_encodeReplaceKeys_roundtrips_N10() public view {
        _assertRoundtrip(Codec.KeyType.Recovery, Codec.KeyType.Recovery, 10);
    }

    function test_exposed_encodeReplaceKeys_roundtripsEmptyKeys()
        public
        view
    {
        // Codec accepts N=0; only the wallet rejects with EmptyKeys.
        _assertRoundtrip(Codec.KeyType.Transaction, Codec.KeyType.Transaction, 0);
    }

    /// @dev Property: encode → decode preserves every field for any seed,
    ///      target kind, signing kind, and N.
    function testFuzz_exposed_encodeReplaceKeys_roundtrips(
        bytes32 seed,
        uint8 kindRaw,
        uint8 signingKindRaw,
        uint8 nRaw
    ) public view {
        Codec.KeyType kind = Codec.KeyType(kindRaw % 3);
        Codec.KeyType signingKind = Codec.KeyType(signingKindRaw % 3);
        uint256 n = nRaw % 11; // [0, 10]

        WOTSPlus.WinternitzAddress memory cur = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory nxt = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzElements memory sig = _fuzzWinternitzElements(seed);
        WOTSPlus.WinternitzAddress[] memory oldKeys = _fuzzWinternitzAddressArray(
            keccak256(abi.encode(seed, "old")),
            n
        );
        WOTSPlus.WinternitzAddress[] memory newKeys = _fuzzWinternitzAddressArray(
            keccak256(abi.encode(seed, "new")),
            n
        );

        bytes memory encoded = codec.exposed_encodeReplaceKeys(
            kind,
            signingKind,
            n,
            cur,
            nxt,
            sig,
            oldKeys,
            newKeys
        );
        assertEq(encoded.length, 2368 + 2 * n * 64);

        WOTSPlusCodecHarness.DecodedReplaceKeys memory out = codec
            .exposed_decodeReplaceKeys(encoded);

        assertTrue(out.kind == kind);
        assertTrue(out.signingKind == signingKind);
        assertEq(out.n, n);
        assertEq(out.currentKey.publicSeed, cur.publicSeed);
        assertEq(out.currentKey.publicKeyHash, cur.publicKeyHash);
        assertEq(out.nextKey.publicSeed, nxt.publicSeed);
        assertEq(out.nextKey.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(out.pqSig.elements[i], sig.elements[i]);
        }
        assertEq(out.oldKeys.length, n);
        assertEq(out.newKeys.length, n);
        for (uint256 i = 0; i < n; i++) {
            assertEq(out.oldKeys[i].publicSeed, oldKeys[i].publicSeed);
            assertEq(out.oldKeys[i].publicKeyHash, oldKeys[i].publicKeyHash);
            assertEq(out.newKeys[i].publicSeed, newKeys[i].publicSeed);
            assertEq(out.newKeys[i].publicKeyHash, newKeys[i].publicKeyHash);
        }
    }

    function _assertRoundtrip(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        uint256 n
    ) internal view {
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
            memory oldKeys = new WOTSPlus.WinternitzAddress[](n);
        WOTSPlus.WinternitzAddress[]
            memory newKeys = new WOTSPlus.WinternitzAddress[](n);
        for (uint256 i = 0; i < n; i++) {
            oldKeys[i] = WOTSPlus.WinternitzAddress(
                bytes32(10 + i * 2),
                bytes32(11 + i * 2)
            );
            newKeys[i] = WOTSPlus.WinternitzAddress(
                bytes32(100 + i * 2),
                bytes32(101 + i * 2)
            );
        }
        bytes memory encoded = codec.exposed_encodeReplaceKeys(
            kind,
            signingKind,
            n,
            cur,
            nxt,
            sig,
            oldKeys,
            newKeys
        );
        WOTSPlusCodecHarness.DecodedReplaceKeys memory out = codec
            .exposed_decodeReplaceKeys(encoded);
        assertTrue(out.kind == kind);
        assertTrue(out.signingKind == signingKind);
        assertEq(out.n, n);
        assertEq(out.oldKeys.length, n);
        assertEq(out.newKeys.length, n);
        for (uint256 i = 0; i < n; i++) {
            assertEq(out.oldKeys[i].publicSeed, oldKeys[i].publicSeed);
            assertEq(out.oldKeys[i].publicKeyHash, oldKeys[i].publicKeyHash);
            assertEq(out.newKeys[i].publicSeed, newKeys[i].publicSeed);
            assertEq(out.newKeys[i].publicKeyHash, newKeys[i].publicKeyHash);
        }
    }
}
