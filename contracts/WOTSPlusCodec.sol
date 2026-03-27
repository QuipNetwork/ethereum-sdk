// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

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
    /// @param payload The packed operation or init payload.
    /// @return owner The PQ owner extracted from the payload head.
    function extractPqOwner(
        bytes calldata payload
    ) internal pure returns (WOTSPlus.WinternitzAddress calldata owner) {
        assembly {
            owner := payload.offset // 0
        }
    }

    /// @dev Extracts the WinternitzElements at offset 64 (after pqOwner).
    /// @param payload The packed operation payload.
    /// @return sig The PQ signature extracted after the owner.
    function extractPqSig(
        bytes calldata payload
    ) internal pure returns (WOTSPlus.WinternitzElements calldata sig) {
        assembly {
            sig := add(payload.offset, 64) // PQ_OWNER_SIZE
        }
    }

    /// @dev Extracts 10 recovery keys at offset 2208 (after pqOwner + pqSig).
    /// @param payload The packed operation payload.
    /// @return keys The 10 recovery keys extracted after the owner and signature.
    function extractRecoveryKeys(
        bytes calldata payload
    ) internal pure returns (WOTSPlus.WinternitzAddress[10] calldata keys) {
        assembly {
            keys := add(payload.offset, 2208) // PQ_OWNER_SIZE + PQ_SIG_SIZE
        }
    }

    /// @dev Extract recovery keys from init payload (no pqSig, keys follow pqOwner directly).
    /// @param payload The packed init or migrator payload.
    /// @return keys The 10 recovery keys extracted after the owner.
    function extractInitRecoveryKeys(
        bytes calldata payload
    ) internal pure returns (WOTSPlus.WinternitzAddress[10] calldata keys) {
        assembly {
            keys := add(payload.offset, 64) // PQ_OWNER_SIZE
        }
    }

    /// @dev Extracts verifier data starting at offset 2848 (2208 bytes: 1 address + 1 sig).
    /// @param payload The packed operation payload.
    /// @return The raw verifier bytes slice.
    function extractVerifiers(
        bytes calldata payload
    ) internal pure returns (bytes calldata) {
        return payload[2848:5056];
    }

    /// @dev Extracts the shouldMigrate flag and migrator payload from the upgrade data.
    ///      [5056] = 1-byte boolean, [5057:5761) = 704-byte migrator payload (init layout).
    /// @param payload The packed upgrade payload.
    /// @return shouldMigrate True if state migration is required.
    /// @return migratorPayload The 704-byte init-layout payload for the new implementation.
    function extractMigrators(
        bytes calldata payload
    ) internal pure returns (bool shouldMigrate, bytes calldata migratorPayload) {
        shouldMigrate = uint8(payload[5056]) != 0;
        migratorPayload = payload[5057:5761];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          HASHERS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev keccak256(abi.encode(chainid, wallet, s1, h1, s2, h2))
    ///      Used by changePqOwner, recoverWallet.
    /// @param s1 The public seed of the current signer.
    /// @param h1 The public key hash of the current signer.
    /// @param s2 The public seed of the new PQ owner.
    /// @param h2 The public key hash of the new PQ owner.
    /// @return The signing digest.
    function keyRotationDigest(
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2
    ) internal view returns (bytes32) {
        return EfficientHashLib.hash(
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(this)))),
            s1, h1, s2, h2
        );
    }

    /// @dev keccak256(abi.encode(chainid, wallet, s1, h1, s2, h2, to, value))
    ///      Used by transferWithWinternitz.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the next PQ owner.
    /// @param h2 The public key hash of the next PQ owner.
    /// @param to The ETH transfer recipient.
    /// @param value The ETH amount to transfer.
    /// @return The signing digest.
    function transferDigest(
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address to,
        uint256 value
    ) internal view returns (bytes32) {
        return EfficientHashLib.hash(
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(this)))),
            s1, h1, s2, h2,
            bytes32(uint256(uint160(to))),
            bytes32(value)
        );
    }

    /// @dev keccak256(abi.encode(chainid, wallet, s1, h1, s2, h2, target, opdataHash))
    ///      Caller must pre-hash opdata: keccak256(opdata).
    ///      Used by executeWithWinternitz.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the next PQ owner.
    /// @param h2 The public key hash of the next PQ owner.
    /// @param target The address of the contract to call.
    /// @param opdataHash The keccak256 hash of the calldata to execute.
    /// @return The signing digest.
    function executeDigest(
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address target,
        bytes32 opdataHash
    ) internal view returns (bytes32) {
        return EfficientHashLib.hash(
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(this)))),
            s1, h1, s2, h2,
            bytes32(uint256(uint160(target))),
            opdataHash
        );
    }

    /// @dev keccak256(abi.encode(chainid, wallet, s1, h1, s2, h2, keysHash))
    ///      Used by addRecoveryKeys, replenishRecoveryKeys.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the next PQ owner.
    /// @param h2 The public key hash of the next PQ owner.
    /// @param keysHash The keccak256 hash of the abi-encoded recovery keys array.
    /// @return The signing digest.
    function keyManagementDigest(
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 keysHash
    ) internal view returns (bytes32) {
        return EfficientHashLib.hash(
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(this)))),
            s1, h1, s2, h2,
            keysHash
        );
    }

    /// @dev keccak256(abi.encode(chainid, wallet, newImpl, s1, h1, s2, h2))
    ///      Used by verifyUpgrade.
    /// @param newImplementation The address of the new UUPS implementation.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the upgrade signer.
    /// @param h2 The public key hash of the upgrade signer.
    /// @return The signing digest.
    function upgradeDigest(
        address newImplementation,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2
    ) internal view returns (bytes32) {
        return EfficientHashLib.hash(
            bytes32(block.chainid),
            bytes32(uint256(uint160(address(this)))),
            bytes32(uint256(uint160(newImplementation))),
            s1, h1, s2, h2
        );
    }
}
