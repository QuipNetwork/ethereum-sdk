// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/deprecated/wots/WOTSPlusCodec.sol";

import {Test} from "forge-std-1.14.0/Test.sol";
import {WOTSPlusCodecHarness} from "../harness/WOTSPlusCodecHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

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

    /// @dev Build a 2048-byte init payload with known values.
    ///      Layout: disaster key (64) + ownership key (64) + 10 transaction keys (640) +
    ///              10 recovery keys (640) + 10 verification keys (640).
    ///      Disaster key seeds are at (startSeed+500, startSeed+501); ownership key seeds
    ///      are at (startSeed+600, startSeed+601). Both avoid colliding with the
    ///      txn/recovery/verification seed ranges used by existing tests.
    function _buildInitPayload(uint256 startSeed) internal pure returns (bytes memory payload) {
        // Disaster recovery key (64 bytes)
        payload = abi.encodePacked(bytes32(startSeed + 500), bytes32(startSeed + 501));
        // Ownership key (64 bytes)
        payload = abi.encodePacked(payload, bytes32(startSeed + 600), bytes32(startSeed + 601));
        // 10 transaction keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, bytes32(startSeed + i * 2), bytes32(startSeed + 1 + i * 2));
        }
        // 10 recovery keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, bytes32(startSeed + 100 + i * 2), bytes32(startSeed + 101 + i * 2));
        }
        // 10 verification keys (640 bytes)
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, bytes32(startSeed + 200 + i * 2), bytes32(startSeed + 201 + i * 2));
        }
    }

    /// @dev Build a 6529-byte upgrade payload with known values.
    ///      Layout: currentKey(64) + nextKey(64) + pqSig(2144) + verifier(64) + verifySig(2144) + shouldMigrate(1) + migratorPayload(2048)
    function _buildUpgradePayload(uint256 seed) internal pure returns (bytes memory payload) {
        // currentKey (64)
        payload = abi.encodePacked(bytes32(seed), bytes32(seed + 1));
        // nextKey (64)
        payload = abi.encodePacked(payload, bytes32(seed + 2), bytes32(seed + 3));
        // pqSig (67 x 32 = 2144)
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 1000 + i));
        }
        // verifier (64)
        payload = abi.encodePacked(payload, bytes32(seed + 2000), bytes32(seed + 2001));
        // verifySig (67 x 32 = 2144)
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 3000 + i));
        }
        // shouldMigrate (1)
        payload = abi.encodePacked(payload, uint8(1));
        // migratorPayload (2048)
        payload = abi.encodePacked(payload, _buildInitPayload(seed + 5000));
    }

    /// @dev Build a 2272-byte auth-rotation prefix payload — the shared
    ///      `currentKey | nextKey | pqSig` shape that prefixes most authenticated
    ///      payloads (execute, withdrawDeposit, replaceKeys, ownership transfer,
    ///      4337 user-op signature).
    ///      Layout: currentKey(64) + nextKey(64) + pqSig(2144).
    function _buildAuthPrefixPayload(uint256 seed) internal pure returns (bytes memory payload) {
        payload = abi.encodePacked(bytes32(seed), bytes32(seed + 1)); // currentKey
        payload = abi.encodePacked(payload, bytes32(seed + 2), bytes32(seed + 3)); // nextKey
        for (uint256 i = 0; i < 67; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 100 + i));
        }
    }

    /// @dev Build an execute payload (≥ 2336 bytes).
    ///      Layout: authPrefix(2272) + target(32) + value(32) + data.
    function _buildExecutePayload(uint256 seed, address target, uint256 value, bytes memory data)
        internal
        pure
        returns (bytes memory payload)
    {
        payload = _buildAuthPrefixPayload(seed);
        payload = abi.encodePacked(payload, bytes32(uint256(uint160(target))), value);
        payload = abi.encodePacked(payload, data);
    }

    /// @dev Build a replaceKeys payload (2368 + 2*N*64 bytes).
    ///      Layout: kind(32) + signingKind(32) + n(32) + currentKey(64) +
    ///              nextKey(64) + pqSig(2144) + oldKeys(n*64) + newKeys(n*64).
    ///      currentKey seeds at (seed, seed+1); nextKey at (seed+2, seed+3);
    ///      pqSig at (seed+100..seed+166); oldKeys[i] at (seed+1000+i*2, ...+1);
    ///      newKeys[i] at (seed+2000+i*2, ...+1). Ranges chosen to avoid
    ///      collisions with other helpers.
    function _buildReplaceKeysPayload(uint256 seed, uint256 n, Codec.KeyType kind, Codec.KeyType signingKind)
        internal
        pure
        returns (bytes memory payload)
    {
        payload = abi.encodePacked(bytes32(uint256(kind)), bytes32(uint256(signingKind)), bytes32(n));
        // currentKey + nextKey + pqSig (2272 bytes)
        payload = abi.encodePacked(payload, _buildAuthPrefixPayload(seed));
        // oldKeys
        for (uint256 i = 0; i < n; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 1000 + i * 2), bytes32(seed + 1001 + i * 2));
        }
        // newKeys
        for (uint256 i = 0; i < n; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 2000 + i * 2), bytes32(seed + 2001 + i * 2));
        }
    }

    /// @dev Build a resetKeyset payload (2976 bytes, fixed).
    ///      Layout: kind(32) + signingKind(32) + currentKey(64) + nextKey(64) +
    ///              pqSig(2144) + newKeys[10](640).
    ///      currentKey/nextKey/pqSig seed offsets match `_buildAuthPrefixPayload`.
    ///      newKeys[i] at (seed+3000+i*2, ...+1).
    function _buildResetKeysetPayload(uint256 seed, Codec.KeyType kind, Codec.KeyType signingKind)
        internal
        pure
        returns (bytes memory payload)
    {
        payload = abi.encodePacked(bytes32(uint256(kind)), bytes32(uint256(signingKind)));
        payload = abi.encodePacked(payload, _buildAuthPrefixPayload(seed));
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(payload, bytes32(seed + 3000 + i * 2), bytes32(seed + 3001 + i * 2));
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

    // --- Fuzz helpers ---
    //
    // These derive WOTS+ keys and signatures from a single bytes32 seed by
    // hashing into separate, non-colliding namespaces. Each helper is pure
    // and deterministic so an encoder roundtrip test can rebuild the same
    // values from the same seed.

    function _fuzzWinternitzAddress(bytes32 seed, uint256 idx)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress memory a)
    {
        a.publicSeed = keccak256(abi.encode(seed, "addr_seed", idx));
        a.publicKeyHash = keccak256(abi.encode(seed, "addr_hash", idx));
    }

    function _fuzzWinternitzElements(bytes32 seed) internal pure returns (WOTSPlus.WinternitzElements memory s) {
        for (uint256 i = 0; i < 67; i++) {
            s.elements[i] = keccak256(abi.encode(seed, "sig", i));
        }
    }

    /// @dev Second signature derived from the same seed in a separate namespace.
    ///      Used by tests that need both a `pqSig` and a `verifySig` from the
    ///      same fuzz input.
    function _fuzzWinternitzElementsAlt(bytes32 seed) internal pure returns (WOTSPlus.WinternitzElements memory s) {
        for (uint256 i = 0; i < 67; i++) {
            s.elements[i] = keccak256(abi.encode(seed, "sig2", i));
        }
    }

    function _fuzzTransactionKeys(bytes32 seed) internal pure returns (WOTSPlus.WinternitzAddress[10] memory arr) {
        for (uint256 i = 0; i < 10; i++) {
            arr[i] = _fuzzWinternitzAddress(seed, 1000 + i);
        }
    }

    function _fuzzRecoveryKeys(bytes32 seed) internal pure returns (WOTSPlus.WinternitzAddress[10] memory arr) {
        for (uint256 i = 0; i < 10; i++) {
            arr[i] = _fuzzWinternitzAddress(seed, 2000 + i);
        }
    }

    function _fuzzVerificationKeys(bytes32 seed) internal pure returns (WOTSPlus.WinternitzAddress[10] memory arr) {
        for (uint256 i = 0; i < 10; i++) {
            arr[i] = _fuzzWinternitzAddress(seed, 4000 + i);
        }
    }

    /// @dev Transitional [5]-tx-keys fuzz helper. Retained for saveWallet /
    ///      transferOwnership encoders that still use a [5] transaction batch
    ///      until phases 3 and 4 of the always-10 work.
    function _fuzzTransactionKeysLegacy5(bytes32 seed)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[5] memory arr)
    {
        for (uint256 i = 0; i < 5; i++) {
            arr[i] = _fuzzWinternitzAddress(seed, 1000 + i);
        }
    }

    function _fuzzWinternitzAddressArray(bytes32 seed, uint256 numKeys)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[] memory arr)
    {
        arr = new WOTSPlus.WinternitzAddress[](numKeys);
        for (uint256 i = 0; i < numKeys; i++) {
            arr[i] = _fuzzWinternitzAddress(seed, 3000 + i);
        }
    }

    /// @dev 65-byte (r ++ s ++ v) ECDSA signature derived from a seed.
    function _fuzzEcdsaSignature(bytes32 seed) internal pure returns (bytes memory) {
        return abi.encodePacked(
            keccak256(abi.encode(seed, "ecdsa_r")),
            keccak256(abi.encode(seed, "ecdsa_s")),
            uint8(uint256(seed) % 2 == 0 ? 27 : 28)
        );
    }
}
