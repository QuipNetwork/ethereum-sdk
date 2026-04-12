// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeOwnershipTransfer is WOTSPlusCodecTest {
    function test_exposed_decodeOwnershipTransfer_decodesCorrectly() public view {
        bytes memory base = _buildChangePqOwnerPayload(10);
        address newOwner = address(0xBEEF);
        bytes memory payload = abi.encodePacked(base, bytes32(uint256(uint160(newOwner))));

        (
            WOTSPlus.WinternitzAddress memory pq,,
            address decodedOwner
        ) = codec.exposed_decodeOwnershipTransfer(payload);

        assertEq(pq.publicSeed, bytes32(uint256(10)));
        assertEq(pq.publicKeyHash, bytes32(uint256(11)));
        assertEq(decodedOwner, newOwner);
    }

    function test_exposed_encodeOwnershipTransfer_roundTrips() public view {
        WOTSPlus.WinternitzAddress memory pq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(42)),
            publicKeyHash: bytes32(uint256(43))
        });
        bytes32[67] memory elems;
        for (uint256 i = 0; i < 67; i++) elems[i] = bytes32(uint256(100 + i));
        WOTSPlus.WinternitzElements memory sig = WOTSPlus.WinternitzElements({ elements: elems });
        address newOwner = address(0xCAFE);

        bytes memory encoded = codec.exposed_encodeOwnershipTransfer(pq, sig, newOwner);
        assertEq(encoded.length, 2240);

        (
            WOTSPlus.WinternitzAddress memory decodedPq,
            WOTSPlus.WinternitzElements memory decodedSig,
            address decodedOwner
        ) = codec.exposed_decodeOwnershipTransfer(encoded);

        assertEq(decodedPq.publicSeed, pq.publicSeed);
        assertEq(decodedPq.publicKeyHash, pq.publicKeyHash);
        assertEq(decodedOwner, newOwner);
        for (uint256 i = 0; i < 67; i++) {
            assertEq(decodedSig.elements[i], elems[i]);
        }
    }

    function test_exposed_decodeOwnershipTransfer_revertsWhen_emptyPayload() public {
        vm.expectRevert();
        codec.exposed_decodeOwnershipTransfer("");
    }
}
