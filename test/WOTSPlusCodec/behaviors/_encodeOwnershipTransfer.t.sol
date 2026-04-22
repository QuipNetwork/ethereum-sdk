// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__encodeOwnershipTransfer is WOTSPlusCodecTest {
    struct Bundle {
        WOTSPlus.WinternitzAddress cur;
        WOTSPlus.WinternitzAddress nxt;
        WOTSPlus.WinternitzElements sig;
        address newOwner;
        WOTSPlus.WinternitzAddress disaster;
        WOTSPlus.WinternitzAddress[5] txn;
        WOTSPlus.WinternitzAddress[10] rec;
    }

    function _sampleBundle() internal pure returns (Bundle memory b) {
        b.cur = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(42)),
            publicKeyHash: bytes32(uint256(43))
        });
        b.nxt = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(44)),
            publicKeyHash: bytes32(uint256(45))
        });
        for (uint256 i = 0; i < 67; i++) {
            b.sig.elements[i] = bytes32(uint256(100 + i));
        }
        b.newOwner = address(0xCAFE);
        b.disaster = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(900)),
            publicKeyHash: bytes32(uint256(901))
        });
        for (uint256 i = 0; i < 5; i++) {
            b.txn[i] = WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(uint256(1000 + i * 2)),
                publicKeyHash: bytes32(uint256(1001 + i * 2))
            });
        }
        for (uint256 i = 0; i < 10; i++) {
            b.rec[i] = WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(uint256(2000 + i * 2)),
                publicKeyHash: bytes32(uint256(2001 + i * 2))
            });
        }
    }

    function test_exposed_encodeOwnershipTransfer_producesCorrectLength()
        public
        view
    {
        Bundle memory b = _sampleBundle();
        bytes memory encoded = codec.exposed_encodeOwnershipTransfer(
            b.cur,
            b.nxt,
            b.sig,
            b.newOwner,
            b.disaster,
            b.txn,
            b.rec
        );
        assertEq(encoded.length, 3328);
    }

    function test_exposed_encodeOwnershipTransfer_roundtrips() public view {
        Bundle memory b = _sampleBundle();
        bytes memory encoded = codec.exposed_encodeOwnershipTransfer(
            b.cur,
            b.nxt,
            b.sig,
            b.newOwner,
            b.disaster,
            b.txn,
            b.rec
        );

        (
            WOTSPlus.WinternitzAddress memory dCur,
            WOTSPlus.WinternitzAddress memory dNxt,
            WOTSPlus.WinternitzElements memory dSig,
            address dOwner,
            WOTSPlus.WinternitzAddress memory dDisaster,
            WOTSPlus.WinternitzAddress[5] memory dTxn,
            WOTSPlus.WinternitzAddress[10] memory dRec
        ) = codec.exposed_decodeOwnershipTransfer(encoded);

        assertEq(dCur.publicSeed, b.cur.publicSeed);
        assertEq(dCur.publicKeyHash, b.cur.publicKeyHash);
        assertEq(dNxt.publicSeed, b.nxt.publicSeed);
        assertEq(dNxt.publicKeyHash, b.nxt.publicKeyHash);
        assertEq(dOwner, b.newOwner);
        assertEq(dDisaster.publicSeed, b.disaster.publicSeed);
        assertEq(dDisaster.publicKeyHash, b.disaster.publicKeyHash);
        for (uint256 i = 0; i < 5; i++) {
            assertEq(dTxn[i].publicSeed, b.txn[i].publicSeed);
            assertEq(dTxn[i].publicKeyHash, b.txn[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(dRec[i].publicSeed, b.rec[i].publicSeed);
            assertEq(dRec[i].publicKeyHash, b.rec[i].publicKeyHash);
        }
        for (uint256 i = 0; i < 67; i++) {
            assertEq(dSig.elements[i], b.sig.elements[i]);
        }
    }
}
