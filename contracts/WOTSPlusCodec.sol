// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
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
///      changePqOwner payload layout (2208 bytes):
///      [0:64)      WinternitzAddress     — newPqOwner
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
///
///      execute payload layout (2272 + N bytes):
///      [0:64)      WinternitzAddress     — nextPqOwner
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
///      [2208:2240) bytes32               — target (left-padded address)
///      [2240:2272) uint256               — value
///      [2272:...)  bytes                 — data (dynamic tail)
///
///      recoverWallet payload layout (2272 bytes):
///      [0:64)      WinternitzAddress     — recoveryKey
///      [64:128)    WinternitzAddress     — newPqOwner
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///
///      keyManagement payload layout (2208 + N*64 bytes, used by addRecoveryKeys & replenishRecoveryKeys):
///      [0:64)      WinternitzAddress     — nextPqOwner
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
///      [2208:...)  WinternitzAddress[]   — newRecoveryKeys (N x 64)
///
///      ERC-4337 UserOp signature layout (2208 bytes, used by validateUserOp):
///      [0:64)      WinternitzAddress     — nextPqOwner (publicSeed ++ publicKeyHash)
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
///
///      recoveryUpgrade payload layout (2208 bytes):
///      [0:64)      WinternitzAddress     — recoveryKey (publicSeed ++ publicKeyHash)
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
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
    bytes32 internal constant EXECUTE_TAG      = keccak256("quip.digest.execute");
    bytes32 internal constant KEY_MGMT_TAG     = keccak256("quip.digest.keyManagement");
    bytes32 internal constant UPGRADE_TAG       = keccak256("quip.digest.upgrade");
    bytes32 internal constant VERIFICATION_TAG = keccak256("quip.digest.verification");
    bytes32 internal constant UPGRADE_RECOVERY_TAG = keccak256("quip.digest.upgradeRecovery");
    bytes32 internal constant ERC4337_EXECUTE_TAG  = keccak256("quip.digest.erc4337Execute");
    bytes32 internal constant WITHDRAW_DEPOSIT_TAG = keccak256("quip.digest.withdrawDeposit");

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
    ///      Layout: [0:64) authKey, [64:2208) pqSig.
    ///      Used by both `upgradeToAndCall` (authKey = nextPqOwner) and
    ///      `recoveryUpgrade` (authKey = recoveryKey).
    /// @param data The packed upgrade payload.
    /// @return nextPqOwner The auth key at offset 0.
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

    /// @dev Decodes the changePqOwner payload.
    ///      Layout: [0:64) newPqOwner, [64:2208) pqSig.
    /// @param payload The packed changePqOwner payload (2208 bytes).
    /// @return newPqOwner The new PQ owner at offset 0.
    /// @return pqSig The PQ signature at offset 64.
    function decodeChangePqOwner(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        assembly {
            newPqOwner := payload.offset
            pqSig := add(payload.offset, 64)
        }
    }

    /// @dev Decodes the ERC-4337 UserOp signature payload.
    ///      Layout: [0:64) nextPqOwner, [64:2208) pqSig.
    ///      Same layout as changePqOwner.
    /// @param sig The UserOp signature bytes.
    /// @return nextPqOwner The next PQ owner at offset 0.
    /// @return pqSig The PQ signature at offset 64.
    function decodeUserOpSignature(
        bytes calldata sig
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        assembly {
            nextPqOwner := sig.offset
            pqSig := add(sig.offset, 64)
        }
    }

    /// @dev Decodes the execute payload.
    ///      Layout: [0:64) nextPqOwner, [64:2208) pqSig, [2208:2240) target,
    ///              [2240:2272) value, [2272:...) data.
    /// @param payload The packed execute payload (>= 2272 bytes).
    /// @return nextPqOwner The next PQ owner at offset 0.
    /// @return pqSig The PQ signature at offset 64.
    /// @return target The recipient or contract address at offset 2208 (left-padded).
    /// @return value The ETH amount at offset 2240.
    /// @return data The calldata tail starting at offset 2272 (empty for pure transfers).
    function decodeExecute(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            address target,
            uint256 value,
            bytes calldata data
        )
    {
        assembly {
            nextPqOwner := payload.offset
            pqSig := add(payload.offset, 64)
            target := calldataload(add(payload.offset, 2208))
            value := calldataload(add(payload.offset, 2240))
        }
        data = payload[2272:];
    }

    /// @dev Decodes the withdrawDeposit payload.
    ///      Layout: [0:64) nextPqOwner, [64:2208) pqSig, [2208:2240) to, [2240:2272) amount.
    /// @param payload The packed withdrawDeposit payload (2272 bytes).
    /// @return nextPqOwner The next PQ owner at offset 0.
    /// @return pqSig The PQ signature at offset 64.
    /// @return to The withdrawal recipient at offset 2208 (left-padded).
    /// @return amount The withdrawal amount at offset 2240.
    function decodeWithdrawDeposit(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            address to,
            uint256 amount
        )
    {
        assembly {
            nextPqOwner := payload.offset
            pqSig := add(payload.offset, 64)
            to := calldataload(add(payload.offset, 2208))
            amount := calldataload(add(payload.offset, 2240))
        }
    }

    /// @dev Decodes the recoverWallet payload.
    ///      Layout: [0:64) recoveryKey, [64:128) newPqOwner, [128:2272) pqSig.
    /// @param payload The packed recoverWallet payload (2272 bytes).
    /// @return recoveryKey The recovery key at offset 0.
    /// @return newPqOwner The new PQ owner at offset 64.
    /// @return pqSig The PQ signature at offset 128.
    function decodeRecoverWallet(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata recoveryKey,
            WOTSPlus.WinternitzAddress calldata newPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        assembly {
            recoveryKey := payload.offset
            newPqOwner := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
        }
    }

    /// @dev Decodes the keyManagement payload (used by addRecoveryKeys & replenishRecoveryKeys).
    ///      Layout: [0:64) nextPqOwner, [64:2208) pqSig, [2208:...) keys (N x 64).
    /// @param payload The packed keyManagement payload (>= 2208 bytes).
    /// @return nextPqOwner The next PQ owner at offset 0.
    /// @return pqSig The PQ signature at offset 64.
    /// @return newRecoveryKeys The recovery keys starting at offset 2208 (length inferred).
    function decodeKeyManagement(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata nextPqOwner,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
        )
    {
        assembly {
            nextPqOwner := payload.offset
            pqSig := add(payload.offset, 64)
            newRecoveryKeys.offset := add(payload.offset, 2208)
            newRecoveryKeys.length := div(sub(payload.length, 2208), 64)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ENCODERS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Encodes the changePqOwner payload.
    /// @param newPqOwner The new PQ owner key.
    /// @param pqSig The PQ signature.
    /// @return The packed payload (2208 bytes).
    function encodeChangePqOwner(
        WOTSPlus.WinternitzAddress memory newPqOwner,
        WOTSPlus.WinternitzElements memory pqSig
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            newPqOwner.publicSeed, newPqOwner.publicKeyHash,
            pqSig.elements
        );
    }

    /// @dev Encodes the execute payload.
    /// @param nextPqOwner The next PQ owner key.
    /// @param pqSig The PQ signature.
    /// @param target The recipient or contract address.
    /// @param value The ETH amount to send.
    /// @param data The calldata for contract calls (empty for pure transfers).
    /// @return The packed payload (>= 2272 bytes).
    function encodeExecute(
        WOTSPlus.WinternitzAddress memory nextPqOwner,
        WOTSPlus.WinternitzElements memory pqSig,
        address target,
        uint256 value,
        bytes memory data
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            nextPqOwner.publicSeed, nextPqOwner.publicKeyHash,
            pqSig.elements,
            bytes32(uint256(uint160(target))),
            value,
            data
        );
    }

    /// @dev Encodes the recoverWallet payload.
    /// @param recoveryKey The recovery key to use.
    /// @param newPqOwner The new PQ owner key.
    /// @param pqSig The PQ signature from the recovery key.
    /// @return The packed payload (2272 bytes).
    function encodeRecoverWallet(
        WOTSPlus.WinternitzAddress memory recoveryKey,
        WOTSPlus.WinternitzAddress memory newPqOwner,
        WOTSPlus.WinternitzElements memory pqSig
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            recoveryKey.publicSeed, recoveryKey.publicKeyHash,
            newPqOwner.publicSeed, newPqOwner.publicKeyHash,
            pqSig.elements
        );
    }

    /// @dev Encodes the keyManagement payload (used by addRecoveryKeys & replenishRecoveryKeys).
    /// @param nextPqOwner The next PQ owner key.
    /// @param pqSig The PQ signature.
    /// @param newRecoveryKeys The recovery keys to add or set.
    /// @return The packed payload (2208 + N*64 bytes).
    function encodeKeyManagement(
        WOTSPlus.WinternitzAddress memory nextPqOwner,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[] memory newRecoveryKeys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(
            nextPqOwner.publicSeed, nextPqOwner.publicKeyHash,
            pqSig.elements
        );
        for (uint256 i = 0; i < newRecoveryKeys.length; i++) {
            payload = abi.encodePacked(
                payload,
                newRecoveryKeys[i].publicSeed,
                newRecoveryKeys[i].publicKeyHash
            );
        }
        return payload;
    }

    /// @dev Encodes the ERC-4337 UserOp signature payload.
    /// @param nextPqOwner The next PQ owner key.
    /// @param pqSig The PQ signature.
    /// @return The packed signature (2208 bytes).
    function encodeUserOpSignature(
        WOTSPlus.WinternitzAddress memory nextPqOwner,
        WOTSPlus.WinternitzElements memory pqSig
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            nextPqOwner.publicSeed, nextPqOwner.publicKeyHash,
            pqSig.elements
        );
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

    /// @dev keccak256(abi.encode(EXECUTE_TAG, chainId, wallet, s1, h1, s2, h2, target, value, opdataHash, fee))
    ///      Caller must pre-hash opdata: keccak256(opdata).
    ///      Used by execute(bytes). The fee is committed at signing time so the
    ///      factory owner cannot front-run the transaction by raising the fee.
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the next PQ owner.
    /// @param h2 The public key hash of the next PQ owner.
    /// @param target The recipient or contract address.
    /// @param value The ETH amount to send.
    /// @param opdataHash The keccak256 hash of the calldata to execute.
    /// @param fee The expected factory execute fee at signing time.
    /// @return The signing digest.
    function executeDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address target,
        uint256 value,
        bytes32 opdataHash,
        uint256 fee
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            EXECUTE_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            s1, h1, s2, h2,
            bytes32(uint256(uint160(target))),
            bytes32(value),
            opdataHash,
            bytes32(fee)
        );
    }

    /// @dev keccak256(abi.encode(WITHDRAW_DEPOSIT_TAG, chainId, wallet, s1, h1, s2, h2, to, amount))
    ///      Used by withdrawDepositTo(bytes).
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the next PQ owner.
    /// @param h2 The public key hash of the next PQ owner.
    /// @param to The withdrawal recipient.
    /// @param amount The withdrawal amount.
    /// @return The signing digest.
    function withdrawDepositDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address to,
        uint256 amount
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            WITHDRAW_DEPOSIT_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            s1, h1, s2, h2,
            bytes32(uint256(uint160(to))),
            bytes32(amount)
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

    /// @dev keccak256(abi.encode(ERC4337_EXECUTE_TAG, chainId, wallet, s1, h1, s2, h2, userOpHash, fee))
    ///      Used by _validateSignature in the ERC-4337 path. The fee is committed
    ///      at signing time so the factory owner cannot front-run the fee.
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param s1 The public seed of the current PQ owner.
    /// @param h1 The public key hash of the current PQ owner.
    /// @param s2 The public seed of the next PQ owner.
    /// @param h2 The public key hash of the next PQ owner.
    /// @param userOpHash The EntryPoint-computed UserOp hash.
    /// @param fee The expected factory execute fee at signing time.
    /// @return The signing digest.
    function erc4337ExecuteDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 userOpHash,
        uint256 fee
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            ERC4337_EXECUTE_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            s1, h1, s2, h2,
            userOpHash,
            bytes32(fee)
        );
    }

    /// @dev keccak256(abi.encode(UPGRADE_RECOVERY_TAG, chainId, wallet, newImpl, s1, h1, s2, h2))
    ///      Used by recoveryUpgrade.
    /// @param wallet The wallet address to bind the digest to.
    /// @param chainId The chain ID to bind the digest to.
    /// @param newImplementation The address of the new UUPS implementation.
    /// @param s1 The public seed of the current pqOwner.
    /// @param h1 The public key hash of the current pqOwner.
    /// @param s2 The public seed of the recovery key.
    /// @param h2 The public key hash of the recovery key.
    /// @return The signing digest for the recovery key.
    function upgradeRecoveryDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(
            UPGRADE_RECOVERY_TAG,
            bytes32(chainId),
            bytes32(uint256(uint160(wallet))),
            bytes32(uint256(uint160(newImplementation))),
            s1, h1, s2, h2
        );
    }
}
