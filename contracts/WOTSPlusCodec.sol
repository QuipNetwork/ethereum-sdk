// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

/// @title WOTSPlusCodec
/// @dev Init payload layout (704 bytes, used by initialize & migrate):
///      [0:64)      WinternitzAddress     — pqOwner (publicSeed ++ publicKeyHash)
///      [64:704)    WinternitzAddress[10] — recoveryKeys (10 x 64)
///
///      Upgrade payload layout (5121 bytes, used by upgradeToAndCall & verifyUpgrade):
///      [0:64)      WinternitzAddress     — nextPqOwner (publicSeed ++ publicKeyHash)
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
///      [2208:2272) WinternitzAddress     — verifier (publicSeed ++ publicKeyHash)
///      [2272:4416) WinternitzElements    — verifySig (67 x 32)
///      [4416]      uint8                 — shouldMigrate (0x00 = false, 0x01 = true)
///      [4417:5121) bytes                 — migratorPayload (init layout, 704 bytes)
///
///      Constants:
///        RECOVERY_KEY_AMOUNT = 10
///
///      Offset derivation:
///        PQ_OWNER    = 2 x 32                          = 64
///        PQ_SIG      = 67 x 32                         = 2144   → starts at 64
///        VERIFIER    = 2 x 32                          = 64     → starts at 64 + 2144 = 2208
///        VERIFY_SIG  = 67 x 32                         = 2144   → starts at 2208 + 64 = 2272
///        MIGRATE     = 1 (uint8)                                → starts at 2272 + 2144 = 4416
///        MIGRATORS   = 704 (init layout)                        → starts at 4416 + 1 = 4417
library WOTSPlusCodec {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      DOMAIN TAGS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    bytes32 internal constant KEY_ROTATION_TAG = keccak256("quip.digest.keyRotation");
    bytes32 internal constant TRANSFER_TAG     = keccak256("quip.digest.transfer");
    bytes32 internal constant EXECUTE_TAG      = keccak256("quip.digest.execute");
    bytes32 internal constant KEY_MGMT_TAG     = keccak256("quip.digest.keyManagement");
    bytes32 internal constant UPGRADE_TAG       = keccak256("quip.digest.upgrade");
    bytes32 internal constant VERIFICATION_TAG = keccak256("quip.digest.verification");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         DECODERS                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Decodes the init payload into pqOwner and recovery keys.
    ///      Layout: [0:64) pqOwner, [64:704) recoveryKeys[10].
    ///      Used by initialize() and migrate().
    /// @param payload The packed init or migrator payload (704 bytes).
    /// @return pqOwner The PQ owner at offset 0.
    /// @return recoveryKeys The 10 recovery keys at offset 64.
    function decodeInit(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata pqOwner,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        )
    {
        assembly {
            pqOwner := payload.offset
            recoveryKeys := add(payload.offset, 64)
        }
    }

    /// @dev Decodes the upgrade payload's authentication portion.
    ///      Layout: [0:64) nextPqOwner, [64:2208) pqSig.
    ///      Used by upgradeToAndCall().
    /// @param data The packed upgrade payload (5121 bytes).
    /// @return nextPqOwner The next PQ owner at offset 0.
    /// @return pqSig The PQ signature at offset 64.
    function decodeUpgradeAuth(
        bytes calldata data
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        assembly {
            nextPqOwner := data.offset
            pqSig := add(data.offset, 64)
        }
    }

    /// @dev Decodes the upgrade payload's verification portion.
    ///      Layout: [2208:2272) verifier, [2272:4416) verifySig.
    ///      Used by verifyUpgrade().
    /// @param data The packed upgrade payload (5121 bytes).
    /// @return verifier The verifier's WinternitzAddress at offset 2208.
    /// @return verifySig The verifier's WinternitzElements at offset 2272.
    function decodeUpgradeVerification(
        bytes calldata data
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata verifier,
            WOTSPlus.WinternitzElements calldata verifySig
        )
    {
        assembly {
            verifier := add(data.offset, 2208)
            verifySig := add(data.offset, 2272)
        }
    }

    /// @dev Decodes the upgrade payload's migration portion.
    ///      Layout: [4416] shouldMigrate, [4417:5121) migratorPayload.
    ///      Used by upgradeToAndCall().
    /// @param data The packed upgrade payload (5121 bytes).
    /// @return shouldMigrate True if state migration is required.
    /// @return migratorPayload The 704-byte init-layout payload for the new implementation.
    function decodeUpgradeMigration(
        bytes calldata data
    ) internal pure returns (bool shouldMigrate, bytes calldata migratorPayload) {
        shouldMigrate = uint8(data[4416]) != 0;
        migratorPayload = data[4417:5121];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          HASHERS                              */
    /*  NOTE: WOTS+ signatures are incompatible with EIP-712. These  */
    /*  digests use domain tags instead of EIP-712 structured data.  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev keccak256(abi.encode(KEY_ROTATION_TAG, chainId, wallet, s1, h1, s2, h2))
    ///      Used by changePqOwner, recoverWallet.
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param s1 The public seed of the current signer.
    /// @param h1 The public key hash of the current signer.
    /// @param s2 The public seed of the new PQ owner.
    /// @param h2 The public key hash of the new PQ owner.
    /// @return The signing digest.
    function keyRotationDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            KEY_ROTATION_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            s1, h1, s2, h2
        );
    }

    /// @dev keccak256(abi.encode(TRANSFER_TAG, chainId, wallet, s1, h1, s2, h2, to, value))
    ///      Used by transferWithWinternitz.
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the next PQ owner.
    /// @param h2 The public key hash of the next PQ owner.
    /// @param to The ETH transfer recipient.
    /// @param value The ETH amount to transfer.
    /// @return The signing digest.
    function transferDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address to,
        uint256 value
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            TRANSFER_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            s1, h1, s2, h2,
            bytes32(uint256(uint160(to))),
            bytes32(value)
        );
    }

    /// @dev keccak256(abi.encode(EXECUTE_TAG, chainId, wallet, s1, h1, s2, h2, target, opdataHash))
    ///      Caller must pre-hash opdata: keccak256(opdata).
    ///      Used by executeWithWinternitz.
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the next PQ owner.
    /// @param h2 The public key hash of the next PQ owner.
    /// @param target The address of the contract to call.
    /// @param opdataHash The keccak256 hash of the calldata to execute.
    /// @return The signing digest.
    function executeDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address target,
        bytes32 opdataHash
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            EXECUTE_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            s1, h1, s2, h2,
            bytes32(uint256(uint160(target))),
            opdataHash
        );
    }

    /// @dev keccak256(abi.encode(KEY_MGMT_TAG, chainId, wallet, s1, h1, s2, h2, keysHash))
    ///      Used by addRecoveryKeys, replenishRecoveryKeys.
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the next PQ owner.
    /// @param h2 The public key hash of the next PQ owner.
    /// @param keysHash The keccak256 hash of the abi-encoded recovery keys array.
    /// @return The signing digest.
    function keyManagementDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 keysHash
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            KEY_MGMT_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            s1, h1, s2, h2,
            keysHash
        );
    }

    /// @dev keccak256(abi.encode(UPGRADE_TAG, chainId, wallet, newImpl, s1, h1, s2, h2))
    ///      Used by verifyUpgrade.
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param newImplementation The address of the new UUPS implementation.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the upgrade signer.
    /// @param h2 The public key hash of the upgrade signer.
    /// @return The signing digest.
    function upgradeDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            UPGRADE_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            bytes32(uint256(uint160(newImplementation))),
            s1, h1, s2, h2
        );
    }

    /// @dev keccak256(abi.encode(VERIFICATION_TAG, chainId, wallet, newImpl, s1, h1))
    ///      Used by verifyUpgrade (delegatecalled on the new implementation).
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param newImplementation The address of the new UUPS implementation.
    /// @param s1 The public seed of the verifier.
    /// @param h1 The public key hash of the verifier.
    /// @return The verification digest.
    function verificationDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            VERIFICATION_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            bytes32(uint256(uint160(newImplementation))),
            s1, h1
        );
    }
}
