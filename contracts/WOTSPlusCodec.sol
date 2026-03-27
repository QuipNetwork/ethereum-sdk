// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title WOTSPlusCodec
/// @dev Operation payload layout (all offsets in bytes):
///      [0:64)      WinternitzAddress     — pqOwner (publicSeed ++ publicKeyHash)
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
///      [2208:2848) WinternitzAddress[10] — recoveryKeys (10 x 64)
///      [2848:5056) bytes                 — verifier data (1 address + 1 sig = 2208)
///      [5056]      bool                  — shouldMigrate (0x00 = false, 0x01 = true)
///      [5057:5761) WinternitzAddress[11] — migrators (pqOwner + 10 recoveryKeys)
///
///      Init payload layout:
///      [0:64)      WinternitzAddress     — pqOwner
///      [64:704)    WinternitzAddress[10] — recoveryKeys (10 x 64)
///
///      Migrator payload layout (same as init):
///      [0:64)      WinternitzAddress     — new pqOwner
///      [64:704)    WinternitzAddress[10] — new recoveryKeys (10 x 64)
///
///      Constants:
///        RECOVERY_KEY_AMOUNT = 10
///
///      Offset derivation:
///        PQ_OWNER  = 2 x 32                          = 64
///        PQ_SIG    = 67 x 32                          = 2144   → starts at 64
///        REC_KEYS  = RECOVERY_KEY_AMOUNT x 64         = 640    → starts at 64 + 2144 = 2208
///        VERIFIERS = PQ_OWNER + PQ_SIG                = 2208   → starts at 2208 + 640 = 2848
///        MIGRATE   = 1 (bool)                                  → starts at 2848 + 2208 = 5056
///        MIGRATORS = 11 x 64                          = 704    → starts at 5056 + 1 = 5057
library WOTSPlusCodec {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         DECODERS                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Extracts the WinternitzAddress at offset 0.
    function extractPqOwner(
        bytes calldata payload
    ) internal pure returns (WOTSPlus.WinternitzAddress calldata owner) {
        assembly {
            owner := payload.offset // 0
        }
    }

    /// @dev Extracts the WinternitzElements at offset 64 (after pqOwner).
    function extractPqSig(
        bytes calldata payload
    ) internal pure returns (WOTSPlus.WinternitzElements calldata sig) {
        assembly {
            sig := add(payload.offset, 64) // PQ_OWNER_SIZE
        }
    }

    /// @dev Extracts 10 recovery keys at offset 2208 (after pqOwner + pqSig).
    function extractRecoveryKeys(
        bytes calldata payload
    ) internal pure returns (WOTSPlus.WinternitzAddress[10] calldata keys) {
        assembly {
            keys := add(payload.offset, 2208) // PQ_OWNER_SIZE + PQ_SIG_SIZE
        }
    }

    /// @dev Extract recovery keys from init payload (no pqSig, keys follow pqOwner directly).
    function extractInitRecoveryKeys(
        bytes calldata payload
    ) internal pure returns (WOTSPlus.WinternitzAddress[10] calldata keys) {
        assembly {
            keys := add(payload.offset, 64) // PQ_OWNER_SIZE
        }
    }

    /// @dev Extracts verifier data starting at offset 2848 (2208 bytes: 1 address + 1 sig).
    function extractVerifiers(
        bytes calldata payload
    ) internal pure returns (bytes calldata) {
        return payload[2848:5056];
    }

    /// @dev Extracts the shouldMigrate flag and migrator payload from the upgrade data.
    ///      [5056] = 1-byte boolean, [5057:5761) = 704-byte migrator payload (init layout).
    function extractMigrators(
        bytes calldata payload
    ) internal pure returns (bool shouldMigrate, bytes calldata migratorPayload) {
        shouldMigrate = uint8(payload[5056]) != 0;
        migratorPayload = payload[5057:5761];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ENCODERS                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Encodes pqOwner, pqSig, and recovery keys into a packed payload.
    function encode(
        WOTSPlus.WinternitzAddress memory owner,
        WOTSPlus.WinternitzElements memory sig,
        WOTSPlus.WinternitzAddress[10] memory recoveryKeys
    ) internal pure returns (bytes memory) {
        bytes memory result = abi.encodePacked(
            owner.publicSeed,
            owner.publicKeyHash,
            sig.elements
        );
        for (uint256 i = 0; i < 10; i++) {
            result = abi.encodePacked(
                result,
                recoveryKeys[i].publicSeed,
                recoveryKeys[i].publicKeyHash
            );
        }
        return result;
    }

    /// @dev Encodes pqOwner, pqSig, recovery keys, and verifier data into a packed payload.
    function encode(
        WOTSPlus.WinternitzAddress memory owner,
        WOTSPlus.WinternitzElements memory sig,
        WOTSPlus.WinternitzAddress[10] memory recoveryKeys,
        bytes memory verifiers
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(encode(owner, sig, recoveryKeys), verifiers);
    }
}
