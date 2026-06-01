// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodecTest} from "../WOTSPlusCodec.t.sol";
import {WOTSPlusCodec} from "../../../contracts/WOTSPlusCodec.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract WOTSPlusCodec__decodeSaveWallet is WOTSPlusCodecTest {
    /// @dev Build a 4192-byte saveWallet payload with known values.
    ///      Layout: currentDisasterKey(64) + newDisasterKey(64) + pqSig(2144) +
    ///              newTransactionKeys[10](640) + newRecoveryKeys[10](640) +
    ///              newVerificationKeys[10](640).
    function _buildSaveWalletPayload(
        uint256 seed
    ) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(bytes32(seed), bytes32(seed + 1));
        payload = abi.encodePacked(
            payload,
            bytes32(seed + 2),
            bytes32(seed + 3)
        );
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 100 + i));
        }
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(seed + 500 + i * 2),
                bytes32(seed + 501 + i * 2)
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(seed + 700 + i * 2),
                bytes32(seed + 701 + i * 2)
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(seed + 900 + i * 2),
                bytes32(seed + 901 + i * 2)
            );
        }
    }

    function test_exposed_decodeSaveWallet_decodesCorrectly() public view {
        bytes memory payload = _buildSaveWalletPayload(42);
        (
            WOTSPlus.WinternitzAddress memory cur,
            WOTSPlus.WinternitzAddress memory nxt,
            WOTSPlus.WinternitzElements memory sig,
            WOTSPlus.WinternitzAddress[10] memory newTxn,
            WOTSPlus.WinternitzAddress[10] memory newRec,
            WOTSPlus.WinternitzAddress[10] memory newVer
        ) = codec.exposed_decodeSaveWallet(payload);

        assertEq(cur.publicSeed, bytes32(uint256(42)));
        assertEq(cur.publicKeyHash, bytes32(uint256(43)));
        assertEq(nxt.publicSeed, bytes32(uint256(44)));
        assertEq(nxt.publicKeyHash, bytes32(uint256(45)));
        for (uint256 i = 0; i < 67; i++) {
            assertEq(sig.elements[i], bytes32(uint256(42 + 100 + i)));
        }
        for (uint256 i = 0; i < 10; i++) {
            assertEq(newTxn[i].publicSeed, bytes32(uint256(42 + 500 + i * 2)));
            assertEq(
                newTxn[i].publicKeyHash,
                bytes32(uint256(42 + 501 + i * 2))
            );
            assertEq(newRec[i].publicSeed, bytes32(uint256(42 + 700 + i * 2)));
            assertEq(
                newRec[i].publicKeyHash,
                bytes32(uint256(42 + 701 + i * 2))
            );
            assertEq(newVer[i].publicSeed, bytes32(uint256(42 + 900 + i * 2)));
            assertEq(
                newVer[i].publicKeyHash,
                bytes32(uint256(42 + 901 + i * 2))
            );
        }
    }

    function test_exposed_decodeSaveWallet_revertsWhen_extraBytes() public {
        bytes memory payload = _buildSaveWalletPayload(42);
        payload = abi.encodePacked(payload, bytes32(uint256(0xFF)));
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                4192,
                4224
            )
        );
        codec.exposed_decodeSaveWallet(payload);
    }

    function test_exposed_decodeSaveWallet_revertsWhen_emptyPayload() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                4192,
                0
            )
        );
        codec.exposed_decodeSaveWallet("");
    }

    function test_exposed_decodeSaveWallet_revertsWhen_truncatedPayload()
        public
    {
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                4192,
                3000
            )
        );
        codec.exposed_decodeSaveWallet(_filledBytes(3000));
    }

    /// @dev Property: any payload length other than 4192 reverts.
    function testFuzz_exposed_decodeSaveWallet_revertsWhen_wrongLength(
        uint256 len
    ) public {
        len = bound(len, 0, 6000);
        vm.assume(len != 4192);
        vm.expectRevert(
            abi.encodeWithSelector(
                WOTSPlusCodec.MalformedPayload.selector,
                4192,
                len
            )
        );
        codec.exposed_decodeSaveWallet(_filledBytes(len));
    }
}
