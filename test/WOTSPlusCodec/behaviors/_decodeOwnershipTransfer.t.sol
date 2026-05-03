// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../contracts/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeOwnershipTransfer is WOTSPlusCodecTest {
    function _buildOwnershipTransferPayload(
        uint256 seed,
        address newOwner
    ) internal pure returns (bytes memory payload) {
        // Auth portion matches _buildAuthPrefixPayload shape.
        payload = _buildAuthPrefixPayload(seed);
        payload = abi.encodePacked(
            payload,
            bytes32(uint256(uint160(newOwner)))
        );
        // newDisasterKey (64)
        payload = abi.encodePacked(
            payload,
            bytes32(seed + 500),
            bytes32(seed + 501)
        );
        // newTransactionKeys[5] (320)
        for (uint256 i = 0; i < 5; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(seed + 600 + i * 2),
                bytes32(seed + 601 + i * 2)
            );
        }
        // newRecoveryKeys[10] (640)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(seed + 700 + i * 2),
                bytes32(seed + 701 + i * 2)
            );
        }
    }

    function test_exposed_decodeOwnershipTransfer_decodesCorrectly()
        public
        view
    {
        address newOwner = address(0xBEEF);
        bytes memory payload = _buildOwnershipTransferPayload(10, newOwner);

        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            ,
            address decodedOwner,
            WOTSPlus.WinternitzAddress memory newDisaster,
            WOTSPlus.WinternitzAddress[5] memory newTxn,
            WOTSPlus.WinternitzAddress[10] memory newRec
        ) = codec.exposed_decodeOwnershipTransfer(payload);

        assertEq(cur.publicSeed, bytes32(uint256(10)));
        assertEq(cur.publicKeyHash, bytes32(uint256(11)));
        assertEq(nxt.publicSeed, bytes32(uint256(12)));
        assertEq(nxt.publicKeyHash, bytes32(uint256(13)));
        assertEq(decodedOwner, newOwner);
        assertEq(newDisaster.publicSeed, bytes32(uint256(10 + 500)));
        assertEq(newDisaster.publicKeyHash, bytes32(uint256(10 + 501)));
        for (uint256 i = 0; i < 5; i++) {
            assertEq(
                newTxn[i].publicSeed,
                bytes32(uint256(10 + 600 + i * 2))
            );
            assertEq(
                newTxn[i].publicKeyHash,
                bytes32(uint256(10 + 601 + i * 2))
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(
                newRec[i].publicSeed,
                bytes32(uint256(10 + 700 + i * 2))
            );
            assertEq(
                newRec[i].publicKeyHash,
                bytes32(uint256(10 + 701 + i * 2))
            );
        }
    }

    function test_exposed_decodeOwnershipTransfer_revertsWhen_emptyPayload()
        public
    {
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                3328,
                0
            )
        );
        codec.exposed_decodeOwnershipTransfer("");
    }

    function test_exposed_decodeOwnershipTransfer_revertsWhen_wrongLength()
        public
    {
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                3328,
                3327
            )
        );
        codec.exposed_decodeOwnershipTransfer(_filledBytes(3327));
    }

    /// @dev Property: any payload length other than 3328 reverts.
    function testFuzz_exposed_decodeOwnershipTransfer_revertsWhen_wrongLength(
        uint256 len
    ) public {
        len = bound(len, 0, 6000);
        vm.assume(len != 3328);
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                3328,
                len
            )
        );
        codec.exposed_decodeOwnershipTransfer(_filledBytes(len));
    }
}
