// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeSaveWallet is WOTSPlusCodecTest {
    struct Bundle {
        WOTSPlus.WinternitzAddress cur;
        WOTSPlus.WinternitzAddress nxt;
        WOTSPlus.WinternitzElements sig;
        WOTSPlus.WinternitzAddress[5] txn;
        WOTSPlus.WinternitzAddress[10] rec;
    }

    function _sampleBundle() internal pure returns (Bundle memory b) {
        b.cur = WOTSPlus.WinternitzAddress(
            bytes32(uint256(1)),
            bytes32(uint256(2))
        );
        b.nxt = WOTSPlus.WinternitzAddress(
            bytes32(uint256(3)),
            bytes32(uint256(4))
        );
        for (uint256 i = 0; i < 67; i++) {
            b.sig.elements[i] = bytes32(uint256(100 + i));
        }
        for (uint256 i = 0; i < 5; i++) {
            b.txn[i] = WOTSPlus.WinternitzAddress(
                bytes32(uint256(500 + i * 2)),
                bytes32(uint256(501 + i * 2))
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            b.rec[i] = WOTSPlus.WinternitzAddress(
                bytes32(uint256(700 + i * 2)),
                bytes32(uint256(701 + i * 2))
            );
        }
    }

    function test_exposed_encodeSaveWallet_producesCorrectLength() public view {
        Bundle memory b = _sampleBundle();
        bytes memory encoded = codec.exposed_encodeSaveWallet(
            b.cur,
            b.nxt,
            b.sig,
            b.txn,
            b.rec
        );
        // 64 (cur) + 64 (nxt) + 2144 (sig) + 5*64 (txn) + 10*64 (rec) = 3232
        assertEq(encoded.length, 3232);
    }

    function test_exposed_encodeSaveWallet_roundtrips() public view {
        Bundle memory b = _sampleBundle();
        bytes memory encoded = codec.exposed_encodeSaveWallet(
            b.cur,
            b.nxt,
            b.sig,
            b.txn,
            b.rec
        );

        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            WOTSPlus.WinternitzAddress[5] memory dTxn,
            WOTSPlus.WinternitzAddress[10] memory dRec
        ) = codec.exposed_decodeSaveWallet(encoded);

        assertEq(dCur.publicSeed, b.cur.publicSeed);
        assertEq(dCur.publicKeyHash, b.cur.publicKeyHash);
        assertEq(dNxt.publicSeed, b.nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, b.nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], b.sig.elements[i]);
        }
        for (uint256 i = 0; i < 5; i++) {
            assertEq(dTxn[i].publicSeed, b.txn[i].publicSeed);
            assertEq(dTxn[i].publicKeyHash, b.txn[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dRec[i].publicSeed, b.rec[i].publicSeed);
            assertEq(dRec[i].publicKeyHash, b.rec[i].publicKeyHash);
        }
    }

    /// @dev Property: encode → decode preserves every field for any seed.
    ///      Pins the 3232-byte saveWallet layout against encoder/decoder drift.
    function testFuzz_exposed_encodeSaveWallet_roundtrips(
        bytes32 seed
    ) public view {
        WOTSPlus.WinternitzAddress memory cur = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory nxt = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzElements memory sig = _fuzzWinternitzElements(seed);
        WOTSPlus.WinternitzAddress[5] memory txn = _fuzzTransactionKeys(seed);
        WOTSPlus.WinternitzAddress[10] memory rec = _fuzzRecoveryKeys(seed);

        bytes memory encoded = codec.exposed_encodeSaveWallet(
            cur,
            nxt,
            sig,
            txn,
            rec
        );
        assertEq(encoded.length, 3232);

        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            WOTSPlus.WinternitzAddress[5] memory dTxn,
            WOTSPlus.WinternitzAddress[10] memory dRec
        ) = codec.exposed_decodeSaveWallet(encoded);

        assertEq(dCur.publicSeed, cur.publicSeed);
        assertEq(dCur.publicKeyHash, cur.publicKeyHash);
        assertEq(dNxt.publicSeed, nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], sig.elements[i]);
        }
        for (uint256 i = 0; i < 5; i++) {
            assertEq(dTxn[i].publicSeed, txn[i].publicSeed);
            assertEq(dTxn[i].publicKeyHash, txn[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dRec[i].publicSeed, rec[i].publicSeed);
            assertEq(dRec[i].publicKeyHash, rec[i].publicKeyHash);
        }
    }
}
