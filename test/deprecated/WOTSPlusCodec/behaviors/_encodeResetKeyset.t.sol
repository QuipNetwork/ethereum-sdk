// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodecHarness} from "../../harness/WOTSPlusCodecHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeResetKeyset is WOTSPlusCodecTest {
    function test_exposed_encodeResetKeyset_producesCorrectLength() public view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(bytes32(uint256(1)), bytes32(uint256(2)));
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(bytes32(uint256(3)), bytes32(uint256(4)));
        WOTSPlus.WinternitzElements memory sig;
        WOTSPlus.WinternitzAddress[10] memory newKeys;
        for (uint256 i = 0; i < 10; i++) {
            newKeys[i] = WOTSPlus.WinternitzAddress(bytes32(100 + i * 2), bytes32(101 + i * 2));
        }
        bytes memory encoded =
            codec.exposed_encodeResetKeyset(Codec.KeyType.Recovery, Codec.KeyType.Transaction, cur, nxt, sig, newKeys);
        // 32 (kind) + 32 (signingKind) + 64 (cur) + 64 (nxt) + 2144 (sig) +
        // 10 * 64 (newKeys) = 2976
        assertEq(encoded.length, 2976);
    }

    function test_exposed_encodeResetKeyset_roundtrips_txSignTxTarget() public view {
        _assertRoundtrip(Codec.KeyType.Transaction, Codec.KeyType.Transaction);
    }

    function test_exposed_encodeResetKeyset_roundtrips_txSignRecoveryTarget() public view {
        _assertRoundtrip(Codec.KeyType.Recovery, Codec.KeyType.Transaction);
    }

    function test_exposed_encodeResetKeyset_roundtrips_recSignVerifyTarget() public view {
        _assertRoundtrip(Codec.KeyType.Verification, Codec.KeyType.Recovery);
    }

    /// @dev Property: encode → decode preserves every field for any seed,
    ///      target kind, and signing kind.
    function testFuzz_exposed_encodeResetKeyset_roundtrips(bytes32 seed, uint8 kindRaw, uint8 signingKindRaw)
        public
        view
    {
        Codec.KeyType kind = Codec.KeyType(kindRaw % 3);
        Codec.KeyType signingKind = Codec.KeyType(signingKindRaw % 3);

        WOTSPlus.WinternitzAddress memory cur = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory nxt = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzElements memory sig = _fuzzWinternitzElements(seed);
        WOTSPlus.WinternitzAddress[10] memory newKeys;
        bytes32 newSeed = keccak256(abi.encode(seed, "new"));
        for (uint256 i = 0; i < 10; i++) {
            newKeys[i] = _fuzzWinternitzAddress(newSeed, i);
        }

        bytes memory encoded = codec.exposed_encodeResetKeyset(kind, signingKind, cur, nxt, sig, newKeys);
        assertEq(encoded.length, 2976);

        WOTSPlusCodecHarness.DecodedResetKeyset memory out = codec.exposed_decodeResetKeyset(encoded);

        assertTrue(out.kind == kind);
        assertTrue(out.signingKind == signingKind);
        assertEq(out.currentKey.publicSeed, cur.publicSeed);
        assertEq(out.currentKey.publicKeyHash, cur.publicKeyHash);
        assertEq(out.nextKey.publicSeed, nxt.publicSeed);
        assertEq(out.nextKey.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(out.pqSig.elements[i], sig.elements[i]);
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(out.newKeys[i].publicSeed, newKeys[i].publicSeed);
            assertEq(out.newKeys[i].publicKeyHash, newKeys[i].publicKeyHash);
        }
    }

    function _assertRoundtrip(Codec.KeyType kind, Codec.KeyType signingKind) internal view {
        WOTSPlus.WinternitzAddress memory cur = WOTSPlus.WinternitzAddress(bytes32(uint256(1)), bytes32(uint256(2)));
        WOTSPlus.WinternitzAddress memory nxt = WOTSPlus.WinternitzAddress(bytes32(uint256(3)), bytes32(uint256(4)));
        WOTSPlus.WinternitzElements memory sig;
        for (uint256 i = 0; i < 67; i++) {
            sig.elements[i] = bytes32(i + 200);
        }
        WOTSPlus.WinternitzAddress[10] memory newKeys;
        for (uint256 i = 0; i < 10; i++) {
            newKeys[i] = WOTSPlus.WinternitzAddress(bytes32(100 + i * 2), bytes32(101 + i * 2));
        }
        bytes memory encoded = codec.exposed_encodeResetKeyset(kind, signingKind, cur, nxt, sig, newKeys);
        WOTSPlusCodecHarness.DecodedResetKeyset memory out = codec.exposed_decodeResetKeyset(encoded);
        assertTrue(out.kind == kind);
        assertTrue(out.signingKind == signingKind);
        for (uint256 i = 0; i < 10; i++) {
            assertEq(out.newKeys[i].publicSeed, newKeys[i].publicSeed);
            assertEq(out.newKeys[i].publicKeyHash, newKeys[i].publicKeyHash);
        }
    }
}
