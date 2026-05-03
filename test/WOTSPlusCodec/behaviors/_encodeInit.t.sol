// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeInit is WOTSPlusCodecTest {
    function _sampleDisaster()
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory)
    {
        return
            WOTSPlus.WinternitzAddress(
                bytes32(uint256(500)),
                bytes32(uint256(501))
            );
    }

    function _sampleOwnership()
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory)
    {
        return
            WOTSPlus.WinternitzAddress(
                bytes32(uint256(600)),
                bytes32(uint256(601))
            );
    }

    function _sampleTxn()
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[5] memory txn)
    {
        for (uint256 i = 0; i < 5; i++) {
            txn[i] = WOTSPlus.WinternitzAddress(
                bytes32(uint256(i * 2)),
                bytes32(uint256(1 + i * 2))
            );
        }
    }

    function _sampleRec()
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[10] memory rec)
    {
        for (uint256 i = 0; i < 10; i++) {
            rec[i] = WOTSPlus.WinternitzAddress(
                bytes32(uint256(100 + i * 2)),
                bytes32(uint256(101 + i * 2))
            );
        }
    }

    function test_exposed_encodeInit_producesCorrectLength() public view {
        bytes memory encoded = codec.exposed_encodeInit(
            _sampleDisaster(),
            _sampleOwnership(),
            _sampleTxn(),
            _sampleRec()
        );
        assertEq(encoded.length, 1088);
    }

    function test_exposed_encodeInit_roundtrips() public view {
        WOTSPlus.WinternitzAddress memory disaster = _sampleDisaster();
        WOTSPlus.WinternitzAddress memory ownership = _sampleOwnership();
        WOTSPlus.WinternitzAddress[5] memory txn = _sampleTxn();
        WOTSPlus.WinternitzAddress[10] memory rec = _sampleRec();

        bytes memory encoded = codec.exposed_encodeInit(
            disaster,
            ownership,
            txn,
            rec
        );

        (
            WOTSPlus.WinternitzAddress memory dDisaster,
            WOTSPlus.WinternitzAddress memory dOwnership,
            WOTSPlus.WinternitzAddress[5] memory dTxn,
            WOTSPlus.WinternitzAddress[10] memory dRec
        ) = codec.exposed_decodeInit(encoded);

        assertEq(dDisaster.publicSeed, disaster.publicSeed);
        assertEq(dDisaster.publicKeyHash, disaster.publicKeyHash);
        assertEq(dOwnership.publicSeed, ownership.publicSeed);
        assertEq(dOwnership.publicKeyHash, ownership.publicKeyHash);
        for (uint256 i = 0; i < 5; i++) {
            assertEq(dTxn[i].publicSeed, txn[i].publicSeed);
            assertEq(dTxn[i].publicKeyHash, txn[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dRec[i].publicSeed, rec[i].publicSeed);
            assertEq(dRec[i].publicKeyHash, rec[i].publicKeyHash);
        }
    }

    /// @dev Property: encode → decode preserves every field for any seed.
    ///      Catches encoder/decoder offset drift across the 1088-byte init
    ///      layout that handwritten tests can miss.
    function testFuzz_exposed_encodeInit_roundtrips(bytes32 seed) public view {
        WOTSPlus.WinternitzAddress memory disaster = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory ownership = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzAddress[5] memory txn = _fuzzTransactionKeys(seed);
        WOTSPlus.WinternitzAddress[10] memory rec = _fuzzRecoveryKeys(seed);

        bytes memory encoded = codec.exposed_encodeInit(
            disaster,
            ownership,
            txn,
            rec
        );
        assertEq(encoded.length, 1088);

        (
            WOTSPlus.WinternitzAddress memory dDisaster,
            WOTSPlus.WinternitzAddress memory dOwnership,
            WOTSPlus.WinternitzAddress[5] memory dTxn,
            WOTSPlus.WinternitzAddress[10] memory dRec
        ) = codec.exposed_decodeInit(encoded);

        assertEq(dDisaster.publicSeed, disaster.publicSeed);
        assertEq(dDisaster.publicKeyHash, disaster.publicKeyHash);
        assertEq(dOwnership.publicSeed, ownership.publicSeed);
        assertEq(dOwnership.publicKeyHash, ownership.publicKeyHash);
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
