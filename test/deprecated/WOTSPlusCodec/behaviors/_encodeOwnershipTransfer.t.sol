// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeOwnershipTransfer is WOTSPlusCodecTest {
    struct Bundle {
        WOTSPlus.WinternitzAddress cur;
        WOTSPlus.WinternitzAddress nxt;
        WOTSPlus.WinternitzElements sig;
        address newOwner;
        WOTSPlus.WinternitzAddress disaster;
        WOTSPlus.WinternitzAddress[10] txn;
        WOTSPlus.WinternitzAddress[10] rec;
        WOTSPlus.WinternitzAddress[10] ver;
    }

    function _sampleBundle() internal pure returns (Bundle memory b) {
        b.cur = WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(42)), publicKeyHash: bytes32(uint256(43))});
        b.nxt = WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(44)), publicKeyHash: bytes32(uint256(45))});
        for (uint256 i = 0; i < 67; i++) {
            b.sig.elements[i] = bytes32(uint256(100 + i));
        }
        b.newOwner = address(0xCAFE);
        b.disaster =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(900)), publicKeyHash: bytes32(uint256(901))});
        for (uint256 i = 0; i < 10; i++) {
            b.txn[i] = WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(uint256(1000 + i * 2)), publicKeyHash: bytes32(uint256(1001 + i * 2))
            });
        }
        for (uint256 i = 0; i < 10; i++) {
            b.rec[i] = WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(uint256(2000 + i * 2)), publicKeyHash: bytes32(uint256(2001 + i * 2))
            });
        }
        for (uint256 i = 0; i < 10; i++) {
            b.ver[i] = WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(uint256(3000 + i * 2)), publicKeyHash: bytes32(uint256(3001 + i * 2))
            });
        }
    }

    function test_exposed_encodeOwnershipTransfer_producesCorrectLength() public view {
        Bundle memory b = _sampleBundle();
        bytes memory encoded =
            codec.exposed_encodeOwnershipTransfer(b.cur, b.nxt, b.sig, b.newOwner, b.disaster, b.txn, b.rec, b.ver);
        assertEq(encoded.length, 4288);
    }

    function test_exposed_encodeOwnershipTransfer_roundtrips() public view {
        Bundle memory b = _sampleBundle();
        bytes memory encoded =
            codec.exposed_encodeOwnershipTransfer(b.cur, b.nxt, b.sig, b.newOwner, b.disaster, b.txn, b.rec, b.ver);

        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            address dOwner,
            WOTSPlus.WinternitzAddress memory dDisaster,
            WOTSPlus.WinternitzAddress[10] memory dTxn,
            WOTSPlus.WinternitzAddress[10] memory dRec,
            WOTSPlus.WinternitzAddress[10] memory dVer
        ) = codec.exposed_decodeOwnershipTransfer(encoded);

        assertEq(dCur.publicSeed, b.cur.publicSeed);
        assertEq(dCur.publicKeyHash, b.cur.publicKeyHash);
        assertEq(dNxt.publicSeed, b.nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, b.nxt.publicKeyHash);
        assertEq(dOwner, b.newOwner);
        assertEq(dDisaster.publicSeed, b.disaster.publicSeed);
        assertEq(dDisaster.publicKeyHash, b.disaster.publicKeyHash);
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dTxn[i].publicSeed, b.txn[i].publicSeed);
            assertEq(dTxn[i].publicKeyHash, b.txn[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dRec[i].publicSeed, b.rec[i].publicSeed);
            assertEq(dRec[i].publicKeyHash, b.rec[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dVer[i].publicSeed, b.ver[i].publicSeed);
            assertEq(dVer[i].publicKeyHash, b.ver[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], b.sig.elements[i]);
        }
    }

    function _fuzzBundle(bytes32 seed, address newOwner) internal pure returns (Bundle memory b) {
        b.cur = _fuzzWinternitzAddress(seed, 0);
        b.nxt = _fuzzWinternitzAddress(seed, 1);
        b.sig = _fuzzWinternitzElements(seed);
        b.newOwner = newOwner;
        b.disaster = _fuzzWinternitzAddress(seed, 2);
        for (uint256 i = 0; i < 10; i++) {
            b.txn[i] = _fuzzWinternitzAddress(seed, 1000 + i);
        }
        for (uint256 i = 0; i < 10; i++) {
            b.rec[i] = _fuzzWinternitzAddress(seed, 2000 + i);
        }
        for (uint256 i = 0; i < 10; i++) {
            b.ver[i] = _fuzzWinternitzAddress(seed, 3000 + i);
        }
    }

    function _assertBundleRoundtrip(Bundle memory b, bytes memory encoded) internal view {
        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            address dOwner,
            WOTSPlus.WinternitzAddress memory dDisaster,
            WOTSPlus.WinternitzAddress[10] memory dTxn,
            WOTSPlus.WinternitzAddress[10] memory dRec,
            WOTSPlus.WinternitzAddress[10] memory dVer
        ) = codec.exposed_decodeOwnershipTransfer(encoded);

        assertEq(dCur.publicSeed, b.cur.publicSeed);
        assertEq(dCur.publicKeyHash, b.cur.publicKeyHash);
        assertEq(dNxt.publicSeed, b.nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, b.nxt.publicKeyHash);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], b.sig.elements[i]);
        }
        assertEq(dOwner, b.newOwner);
        assertEq(dDisaster.publicSeed, b.disaster.publicSeed);
        assertEq(dDisaster.publicKeyHash, b.disaster.publicKeyHash);
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dTxn[i].publicSeed, b.txn[i].publicSeed);
            assertEq(dTxn[i].publicKeyHash, b.txn[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dRec[i].publicSeed, b.rec[i].publicSeed);
            assertEq(dRec[i].publicKeyHash, b.rec[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dVer[i].publicSeed, b.ver[i].publicSeed);
            assertEq(dVer[i].publicKeyHash, b.ver[i].publicKeyHash);
        }
    }

    /// @dev Property: encode → decode preserves every field for any inputs.
    ///      Pins the 4288-byte ownership-transfer layout — the largest
    ///      auth-prefix-shaped payload, with `newOwner` packed mid-payload
    ///      between the signature tail and the disaster/txn/recovery/verification keysets.
    ///      Bundles inputs into a struct to keep stack depth manageable.
    function testFuzz_exposed_encodeOwnershipTransfer_roundtrips(bytes32 seed, address newOwner) public view {
        Bundle memory b = _fuzzBundle(seed, newOwner);
        bytes memory encoded =
            codec.exposed_encodeOwnershipTransfer(b.cur, b.nxt, b.sig, b.newOwner, b.disaster, b.txn, b.rec, b.ver);
        assertEq(encoded.length, 4288);
        _assertBundleRoundtrip(b, encoded);
    }
}
