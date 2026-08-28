// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeInit is WOTSPlusCodecTest {
    function _sampleDisaster() internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return WOTSPlus.WinternitzAddress(bytes32(uint256(500)), bytes32(uint256(501)));
    }

    function _sampleOwnership() internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return WOTSPlus.WinternitzAddress(bytes32(uint256(600)), bytes32(uint256(601)));
    }

    function _sampleTxn() internal pure returns (WOTSPlus.WinternitzAddress[10] memory txn) {
        for (uint256 i = 0; i < 10; i++) {
            txn[i] = WOTSPlus.WinternitzAddress(bytes32(uint256(i * 2)), bytes32(uint256(1 + i * 2)));
        }
    }

    function _sampleRec() internal pure returns (WOTSPlus.WinternitzAddress[10] memory rec) {
        for (uint256 i = 0; i < 10; i++) {
            rec[i] = WOTSPlus.WinternitzAddress(bytes32(uint256(100 + i * 2)), bytes32(uint256(101 + i * 2)));
        }
    }

    function _sampleVer() internal pure returns (WOTSPlus.WinternitzAddress[10] memory ver) {
        for (uint256 i = 0; i < 10; i++) {
            ver[i] = WOTSPlus.WinternitzAddress(bytes32(uint256(200 + i * 2)), bytes32(uint256(201 + i * 2)));
        }
    }

    function _assertDecodedInit(
        bytes memory encoded,
        WOTSPlus.WinternitzAddress memory disaster,
        WOTSPlus.WinternitzAddress memory ownership,
        WOTSPlus.WinternitzAddress[10] memory txn,
        WOTSPlus.WinternitzAddress[10] memory rec,
        WOTSPlus.WinternitzAddress[10] memory ver
    ) internal view {
        (
            WOTSPlus.WinternitzAddress memory dDisaster,
            WOTSPlus.WinternitzAddress memory dOwnership,
            WOTSPlus.WinternitzAddress[10] memory dTxn,
            WOTSPlus.WinternitzAddress[10] memory dRec,
            WOTSPlus.WinternitzAddress[10] memory dVer
        ) = codec.exposed_decodeInit(encoded);
        _assertEqWinternitzAddress(dDisaster, disaster);
        _assertEqWinternitzAddress(dOwnership, ownership);
        _assertEqKeysets10(dTxn, txn, dRec, rec, dVer, ver);
    }

    function test_exposed_encodeInit_producesCorrectLength() public view {
        bytes memory encoded =
            codec.exposed_encodeInit(_sampleDisaster(), _sampleOwnership(), _sampleTxn(), _sampleRec(), _sampleVer());
        assertEq(encoded.length, 2048);
    }

    function test_exposed_encodeInit_roundtrips() public view {
        WOTSPlus.WinternitzAddress memory disaster = _sampleDisaster();
        WOTSPlus.WinternitzAddress memory ownership = _sampleOwnership();
        WOTSPlus.WinternitzAddress[10] memory txn = _sampleTxn();
        WOTSPlus.WinternitzAddress[10] memory rec = _sampleRec();
        WOTSPlus.WinternitzAddress[10] memory ver = _sampleVer();

        bytes memory encoded = codec.exposed_encodeInit(disaster, ownership, txn, rec, ver);
        _assertDecodedInit(encoded, disaster, ownership, txn, rec, ver);
    }

    /// @dev Property: encode → decode preserves every field for any seed.
    ///      Catches encoder/decoder offset drift across the 2048-byte init
    ///      layout that handwritten tests can miss.
    function testFuzz_exposed_encodeInit_roundtrips(bytes32 seed) public view {
        WOTSPlus.WinternitzAddress memory disaster = _fuzzWinternitzAddress(seed, 0);
        WOTSPlus.WinternitzAddress memory ownership = _fuzzWinternitzAddress(seed, 1);
        WOTSPlus.WinternitzAddress[10] memory txn = _fuzzTransactionKeys(seed);
        WOTSPlus.WinternitzAddress[10] memory rec = _fuzzRecoveryKeys(seed);
        WOTSPlus.WinternitzAddress[10] memory ver = _fuzzVerificationKeys(seed);

        bytes memory encoded = codec.exposed_encodeInit(disaster, ownership, txn, rec, ver);
        assertEq(encoded.length, 2048);
        _assertDecodedInit(encoded, disaster, ownership, txn, rec, ver);
    }
}
