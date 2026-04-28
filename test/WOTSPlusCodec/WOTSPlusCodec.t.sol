// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../contracts/WOTSPlusCodec.sol";

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

    /// @dev Build a 1088-byte init payload with known values.
    ///      Layout: disaster key (64) + ownership key (64) + 5 transaction keys (320) +
    ///              10 recovery keys (640).
    ///      Disaster key seeds are at (startSeed+500, startSeed+501); ownership key seeds
    ///      are at (startSeed+600, startSeed+601). Both avoid colliding with the
    ///      txn/recovery seed ranges used by existing tests.
    function _buildInitPayload(
        uint256 startSeed
    ) internal pure returns (bytes memory payload) {
        // Disaster recovery key (64 bytes)
        payload = abi.encodePacked(
            bytes32(startSeed + 500),
            bytes32(startSeed + 501)
        );
        // Ownership key (64 bytes)
        payload = abi.encodePacked(
            payload,
            bytes32(startSeed + 600),
            bytes32(startSeed + 601)
        );
        // 5 transaction keys (320 bytes)
        for (uint256 i = 0; i < 5; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(startSeed + i * 2),
                bytes32(startSeed + 1 + i * 2)
            );
        }
        // 10 recovery keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                bytes32(startSeed + 100 + i * 2),
                bytes32(startSeed + 101 + i * 2)
            );
        }
    }

    /// @dev Build a 5569-byte upgrade payload with known values.
    ///      Layout: currentKey(64) + nextKey(64) + pqSig(2144) + verifier(64) + verifySig(2144) + shouldMigrate(1) + migratorPayload(1088)
    function _buildUpgradePayload(
        uint256 seed
    ) internal pure returns (bytes memory payload) {
        // currentKey (64)
        payload = abi.encodePacked(bytes32(seed), bytes32(seed + 1));
        // nextKey (64)
        payload = abi.encodePacked(
            payload,
            bytes32(seed + 2),
            bytes32(seed + 3)
        );
        // pqSig (67 x 32 = 2144)
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 1000 + i));
        }
        // verifier (64)
        payload = abi.encodePacked(
            payload,
            bytes32(seed + 2000),
            bytes32(seed + 2001)
        );
        // verifySig (67 x 32 = 2144)
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 3000 + i));
        }
        // shouldMigrate (1)
        payload = abi.encodePacked(payload, uint8(1));
        // migratorPayload (1088)
        payload = abi.encodePacked(payload, _buildInitPayload(seed + 5000));
    }

    /// @dev Build a 2272-byte auth-rotation prefix payload — the shared
    ///      `currentKey | nextKey | pqSig` shape that prefixes most authenticated
    ///      payloads (execute, withdrawDeposit, replaceKeyAt, ownership transfer,
    ///      4337 user-op signature).
    ///      Layout: currentKey(64) + nextKey(64) + pqSig(2144).
    function _buildAuthPrefixPayload(
        uint256 seed
    ) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(bytes32(seed), bytes32(seed + 1)); // currentKey
        payload = abi.encodePacked(
            payload,
            bytes32(seed + 2),
            bytes32(seed + 3)
        ); // nextKey
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 100 + i));
        }
    }

    /// @dev Build an execute payload (≥ 2336 bytes).
    ///      Layout: authPrefix(2272) + target(32) + value(32) + data.
    function _buildExecutePayload(
        uint256 seed,
        address target,
        uint256 value,
        bytes memory data
    ) internal pure returns (bytes memory payload) {
        payload = _buildAuthPrefixPayload(seed);
        payload = abi.encodePacked(
            payload,
            bytes32(uint256(uint160(target))),
            value
        );
        payload = abi.encodePacked(payload, data);
    }

    /// @dev Build a 2336-byte recoverWallet payload.
    ///      Layout: recoveryKey(64) + newRecoveryKey(64) + newTransactionKey(64) + pqSig(2144).
    function _buildRecoverWalletPayload(
        uint256 seed
    ) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(
            bytes32(seed),
            bytes32(seed + 1), // recoveryKey
            bytes32(seed + 5),
            bytes32(seed + 6), // newRecoveryKey
            bytes32(seed + 10),
            bytes32(seed + 11) // newTransactionKey
        );
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 100 + i));
        }
    }

    /// @dev Build a keyManagement payload (2304 + N*64 bytes).
    function _buildKeyManagementPayload(
        uint256 seed,
        uint256 numKeys,
        Codec.KeyType kind
    ) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(bytes32(uint256(kind)));
        payload = abi.encodePacked(
            payload,
            _buildAuthPrefixPayload(seed)
        );
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
