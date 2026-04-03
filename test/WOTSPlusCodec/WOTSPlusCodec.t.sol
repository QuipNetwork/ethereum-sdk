// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {WOTSPlusCodecHarness} from "../harness/WOTSPlusCodecHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title WOTSPlusCodec Base Test
/// @dev Base contract for testing WOTSPlusCodec via harness.
contract WOTSPlusCodecTest is Test {
    WOTSPlusCodecHarness public codec;

    function setUp() public virtual {
        codec = new WOTSPlusCodecHarness();
    }

    function test_setUp() public view {
        assertTrue(address(codec) != address(0));
    }

    // --- Helpers ---

    /// @dev Build a 704-byte init payload with known values.
    function _buildInitPayload(uint256 startSeed) internal pure returns (bytes memory payload) {
        // pqOwner (64 bytes)
        payload = abi.encodePacked(bytes32(startSeed), bytes32(startSeed + 1));
        // 10 recovery keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(startSeed + 100 + i * 2),
                bytes32(startSeed + 101 + i * 2)
            );
        }
    }

    /// @dev Build a 5121-byte upgrade payload with known values.
    function _buildUpgradePayload(uint256 seed) internal pure returns (bytes memory payload) {
        // nextPqOwner (64 bytes)
        payload = abi.encodePacked(bytes32(seed), bytes32(seed + 1));
        // pqSig (67 x 32 = 2144 bytes)
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 1000 + i));
        }
        // verifier (64 bytes)
        payload = abi.encodePacked(payload, bytes32(seed + 2000), bytes32(seed + 2001));
        // verifySig (67 x 32 = 2144 bytes)
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 3000 + i));
        }
        // shouldMigrate (1 byte)
        payload = abi.encodePacked(payload, uint8(1));
        // migratorPayload (704 bytes)
        payload = abi.encodePacked(payload, _buildInitPayload(seed + 5000));
    }

    /// @dev Build a 2208-byte changePqOwner payload.
    function _buildChangePqOwnerPayload(uint256 seed) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(bytes32(seed), bytes32(seed + 1));
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 100 + i));
        }
    }

    /// @dev Build an execute payload (≥ 2272 bytes).
    function _buildExecutePayload(
        uint256 seed,
        address target,
        uint256 value,
        bytes memory data
    ) internal pure returns (bytes memory payload) {
        // nextPqOwner (64) + pqSig (2144) = 2208
        payload = _buildChangePqOwnerPayload(seed);
        // target (32, left-padded) + value (32) = 64
        payload = abi.encodePacked(payload, bytes32(uint256(uint160(target))), value);
        // dynamic data
        payload = abi.encodePacked(payload, data);
    }

    /// @dev Build a 2272-byte recoverWallet payload.
    function _buildRecoverWalletPayload(uint256 seed) internal pure returns (bytes memory payload) {
        // recoveryKey (64) + newPqOwner (64) + pqSig (2144) = 2272
        payload = abi.encodePacked(
            bytes32(seed), bytes32(seed + 1),           // recoveryKey
            bytes32(seed + 10), bytes32(seed + 11)      // newPqOwner
        );
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 100 + i));
        }
    }

    /// @dev Build a keyManagement payload (2208 + N*64 bytes).
    function _buildKeyManagementPayload(uint256 seed, uint256 numKeys)
        internal
        pure
        returns (bytes memory payload)
    {
        payload = _buildChangePqOwnerPayload(seed);
        for (uint256 i = 0; i < numKeys; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(seed + 500 + i * 2),
                bytes32(seed + 501 + i * 2)
            );
        }
    }

    /// @dev Create N zero bytes.
    function _zeros(uint256 n) internal pure returns (bytes memory) {
        return new bytes(n);
    }

    /// @dev Create N bytes filled with 0xAB.
    function _filledBytes(uint256 n) internal pure returns (bytes memory data) {
        data = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            data[i] = 0xAB;
        }
    }
}
