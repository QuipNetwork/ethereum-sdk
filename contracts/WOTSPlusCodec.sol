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
/// @dev All guarded operations carry an explicit (currentKey, nextKey) pair up front,
///      naming the transaction key being consumed and the replacement being installed.
///
///      Init payload layout (1088 bytes, used by initialize & migrate):
///      [0:64)      WinternitzAddress     — disasterRecoveryKey
///      [64:128)    WinternitzAddress     — ownershipKey
///      [128:448)   WinternitzAddress[5]  — transactionKeys (5 x 64)
///      [448:1088)  WinternitzAddress[10] — recoveryKeys (10 x 64)
///
///      upgradeToAndCall payload layout (5569 bytes):
///      [0:64)      WinternitzAddress     — currentKey (publicSeed ++ publicKeyHash)
///      [64:128)    WinternitzAddress     — nextKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///      [2272:2336) WinternitzAddress     — verifier
///      [2336:4480) WinternitzElements    — verifySig (67 x 32)
///      [4480]      uint8                 — shouldMigrate (0x00 = false, 0x01 = true)
///      [4481:5569) bytes                 — migratorPayload (init layout, 1088 bytes)
///
///      recoveryUpgrade payload layout (4416 bytes, no rotation):
///      [0:64)      WinternitzAddress     — recoveryKey
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
///      [2208:2272) WinternitzAddress     — verifier
///      [2272:4416) WinternitzElements    — verifySig (67 x 32)
///
///      changeTransactionKey payload layout (2272 bytes):
///      [0:64)      WinternitzAddress     — currentKey
///      [64:128)    WinternitzAddress     — nextKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///
///      execute payload layout (2336 + N bytes):
///      [0:64)      WinternitzAddress     — currentKey
///      [64:128)    WinternitzAddress     — nextKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///      [2272:2304) bytes32               — target (left-padded address)
///      [2304:2336) uint256               — value
///      [2336:...)  bytes                 — data (dynamic tail)
///
///      withdrawDeposit payload layout (2336 bytes):
///      [0:64)      WinternitzAddress     — currentKey
///      [64:128)    WinternitzAddress     — nextKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///      [2272:2304) bytes32               — to (left-padded address)
///      [2304:2336) uint256               — amount
///
///      ownershipTransfer payload layout (3328 bytes, used by transferOwnership and
///      completeOwnershipHandover):
///      [0:64)      WinternitzAddress     — currentOwnershipKey
///      [64:128)    WinternitzAddress     — newOwnershipKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///      [2272:2304) bytes32               — newOwner (left-padded address)
///      [2304:2368) WinternitzAddress     — newDisasterKey
///      [2368:2688) WinternitzAddress[5]  — newTransactionKeys (5 x 64)
///      [2688:3328) WinternitzAddress[10] — newRecoveryKeys (10 x 64)
///
///      recoverWallet payload layout (2272 bytes):
///      [0:64)      WinternitzAddress     — recoveryKey
///      [64:128)    WinternitzAddress     — newTransactionKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///
///      keyManagement payload layout (2304 + N*64 bytes, used by addKeys and refreshKeys):
///      [0:32)      uint256               — kind (KeyType enum: 0=Txn, 1=Recovery, 2=Verification)
///      [32:96)     WinternitzAddress     — currentKey
///      [96:160)    WinternitzAddress     — nextKey
///      [160:2304)  WinternitzElements    — pqSig (67 x 32)
///      [2304:...)  WinternitzAddress[]   — keys (N x 64)
///
///      verificationKeysReplace payload layout (2368 bytes):
///      [0:64)      WinternitzAddress     — currentKey
///      [64:128)    WinternitzAddress     — nextKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///      [2272:2304) uint256               — index
///      [2304:2368) WinternitzAddress     — newKey
///
///      ERC-4337 UserOp signature layout (2272 bytes, used by validateUserOp):
///      [0:64)      WinternitzAddress     — currentKey
///      [64:128)    WinternitzAddress     — nextKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///
///      ERC-1271 signature layout (2273 bytes, used by isValidSignature):
///      [0:64)      WinternitzAddress     — verifier
///      [64:2208)   WinternitzElements    — pqSig (67 x 32)
///      [2208:2273) bytes                 — ecdsaSig (r(32) ++ s(32) ++ v(1))
///
///      Constants:
///        TRANSACTION_KEY_INIT_AMOUNT = 5
///        RECOVERY_KEY_AMOUNT         = 10
library WOTSPlusCodec {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           TYPES                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Discriminator for the three PQ keysets managed by a QuipWallet.
    /// @dev Travels at the head of the `keyManagement` payload and selects the
    ///      target keyset for `addKeys` / `refreshKeys`. The enum cast performed
    ///      by `decodeKeyManagement` implicitly validates that the on-wire value
    ///      falls within `[0, 2]` (reverts via Solidity 0.8 panic otherwise).
    enum KeyType {
        Transaction,
        Recovery,
        Verification
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    uint256 internal constant TRANSACTION_KEY_INIT_AMOUNT = 5;
    uint256 internal constant RECOVERY_KEY_AMOUNT = 10;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       DOMAIN TAGS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Every digest committed to a WOTS+ signature is prefixed with a unique
    // domain tag. The tag is the first preimage element fed into
    // `EfficientHashLib.hash(...)` alongside chainId, wallet, and the
    // operation-specific fields. Each tag binds a signature to exactly one
    // operation shape so a signature produced for one code path cannot be
    // lifted and replayed against another.
    //
    // Cross-type keyset replay is the subtle case. `addKeys` and `refreshKeys`
    // both take the same `(currentKey, nextKey, pqSig, newKeys[])` payload,
    // and all three keysets (Transaction, Recovery, Verification) share the
    // `_addKeys` / `_rotateKeys` primitives. Without per-kind domain
    // separation, a signature authorizing `addKeys(Recovery, payload)` would
    // hash to the same digest as `addKeys(Verification, payload)` — an
    // attacker who observed one could replay the signature against the other
    // keyset and silently install attacker-controlled keys into a set the
    // owner never intended to modify.
    //
    // The three `*_TAG` constants below (ADD_TRANSACTION_KEYS_TAG,
    // KEY_MGMT_TAG for Recovery, VERIFICATION_KEYS_TAG for Verification) are
    // what prevent that. `keysetDigest(KeyType, ...)` selects the tag from the
    // `kind` argument so the signature preimage includes a kind-specific tag.
    // A signature over one tag does not verify against any of the other two.
    // Do not unify these tags — the distinct tags are load-bearing security,
    // not cosmetic.
    bytes32 internal constant KEY_ROTATION_TAG =
        keccak256("quip.digest.keyRotation");
    bytes32 internal constant EXECUTE_TAG = keccak256("quip.digest.execute");
    /// @dev Recovery-keyset domain tag. Selected by `keysetDigest` when
    ///      `kind == KeyType.Recovery`.
    bytes32 internal constant KEY_MGMT_TAG =
        keccak256("quip.digest.keyManagement");
    /// @dev Transaction-keyset domain tag. Selected by `keysetDigest` when
    ///      `kind == KeyType.Transaction`.
    ///      `refreshKeys(Transaction, …)` is forbidden at the contract level.
    bytes32 internal constant ADD_TRANSACTION_KEYS_TAG =
        keccak256("quip.digest.addTransactionKeys");
    bytes32 internal constant UPGRADE_TAG = keccak256("quip.digest.upgrade");
    bytes32 internal constant VERIFICATION_TAG =
        keccak256("quip.digest.verification");
    bytes32 internal constant UPGRADE_RECOVERY_TAG =
        keccak256("quip.digest.upgradeRecovery");
    bytes32 internal constant ERC4337_EXECUTE_TAG =
        keccak256("quip.digest.erc4337Execute");
    bytes32 internal constant WITHDRAW_DEPOSIT_TAG =
        keccak256("quip.digest.withdrawDeposit");
    bytes32 internal constant TRANSFER_OWNERSHIP_TAG =
        keccak256("quip.digest.transferOwnership");
    bytes32 internal constant COMPLETE_OWNERSHIP_HANDOVER_TAG =
        keccak256("quip.digest.completeOwnershipHandover");
    /// @dev Verification-keyset domain tag. Selected by `keysetDigest` when
    ///      `kind == KeyType.Verification`.
    bytes32 internal constant VERIFICATION_KEYS_TAG =
        keccak256("quip.digest.verificationKeys");
    bytes32 internal constant VERIFICATION_KEYS_REPLACE_TAG =
        keccak256("quip.digest.verificationKeysReplace");
    bytes32 internal constant ERC1271_TAG = keccak256("quip.digest.erc1271");
    /// @dev Disaster-recovery domain tag. Used by `saveWalletDigest` to bind a
    ///      `saveWallet` signature to a specific wallet, chain, and key-rotation pair.
    bytes32 internal constant SAVE_WALLET_TAG =
        keccak256("quip.digest.saveWallet");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         DECODERS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Decodes the init payload into disaster recovery key, ownership key, transaction
    ///      keys, and recovery keys.
    ///      Layout: [0:64) disasterRecoveryKey, [64:128) ownershipKey,
    ///              [128:448) transactionKeys[5], [448:1088) recoveryKeys[10].
    ///      Used by initialize() and migrate().
    /// @param payload The packed init or migrator payload (1088 bytes).
    /// @return disasterRecoveryKey The last-resort WOTS+ rescue key at offset 0.
    /// @return ownershipKey The ownership-transfer WOTS+ key at offset 64.
    /// @return transactionKeys The 5 initial transaction keys at offset 128.
    /// @return recoveryKeys The 10 recovery keys at offset 448.
    function decodeInit(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata disasterRecoveryKey,
            WOTSPlus.WinternitzAddress calldata ownershipKey,
            WOTSPlus.WinternitzAddress[5] calldata transactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys
        )
    {
        assembly {
            disasterRecoveryKey := payload.offset
            ownershipKey := add(payload.offset, 64)
            transactionKeys := add(payload.offset, 128)
            recoveryKeys := add(payload.offset, 448)
        }
    }

    /// @dev Decodes the saveWallet payload.
    ///      Layout: [0:64) currentDisasterKey, [64:128) newDisasterKey,
    ///              [128:2272) pqSig, [2272:2592) newTransactionKeys[5],
    ///              [2592:3232) newRecoveryKeys[10].
    /// @param payload The packed saveWallet payload (3232 bytes).
    function decodeSaveWallet(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentDisasterKey,
            WOTSPlus.WinternitzAddress calldata newDisasterKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[5] calldata newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata newRecoveryKeys
        )
    {
        assembly {
            currentDisasterKey := payload.offset
            newDisasterKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
            newTransactionKeys := add(payload.offset, 2272)
            newRecoveryKeys := add(payload.offset, 2592)
        }
    }

    /// @dev Decodes the upgradeToAndCall payload's authentication portion.
    ///      Layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig.
    /// @param data The packed upgrade payload.
    /// @return currentKey The consumed transaction key at offset 0.
    /// @return nextKey The replacement transaction key at offset 64.
    /// @return pqSig The PQ signature at offset 128.
    function decodeUpgradeAuth(
        bytes calldata data
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        assembly {
            currentKey := data.offset
            nextKey := add(data.offset, 64)
            pqSig := add(data.offset, 128)
        }
    }

    /// @dev Decodes the recoveryUpgrade payload's authentication portion.
    ///      Layout: [0:64) recoveryKey, [64:2208) pqSig.
    ///      Distinct from upgradeToAndCall because no rotation occurs.
    /// @param data The packed recoveryUpgrade payload (4416 bytes).
    /// @return recoveryKey The recovery key at offset 0.
    /// @return pqSig The PQ signature at offset 64.
    function decodeRecoveryUpgradeAuth(
        bytes calldata data
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata recoveryKey,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        assembly {
            recoveryKey := data.offset
            pqSig := add(data.offset, 64)
        }
    }

    /// @dev Decodes the upgradeToAndCall payload's verification portion.
    ///      Layout: [2272:2336) verifier, [2336:4480) verifySig.
    ///      Used by verifyUpgrade() in the upgradeToAndCall path.
    /// @param data The packed upgrade payload (5505 bytes).
    /// @return verifier The verifier's WinternitzAddress at offset 2272.
    /// @return verifySig The verifier's WinternitzElements at offset 2336.
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
            verifier := add(data.offset, 2272)
            verifySig := add(data.offset, 2336)
        }
    }

    /// @dev Decodes the recoveryUpgrade payload's verification portion.
    ///      Layout: [2208:2272) verifier, [2272:4416) verifySig.
    /// @param data The packed recoveryUpgrade payload (4416 bytes).
    /// @return verifier The verifier's WinternitzAddress at offset 2208.
    /// @return verifySig The verifier's WinternitzElements at offset 2272.
    function decodeRecoveryUpgradeVerification(
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

    /// @dev Decodes the upgradeToAndCall payload's migration portion.
    ///      Layout: [4480] shouldMigrate, [4481:5569) migratorPayload.
    /// @param data The packed upgrade payload (5569 bytes).
    /// @return shouldMigrate True if state migration is required.
    /// @return migratorPayload The 1088-byte init-layout payload for the new implementation.
    function decodeUpgradeMigration(
        bytes calldata data
    )
        internal
        pure
        returns (bool shouldMigrate, bytes calldata migratorPayload)
    {
        shouldMigrate = uint8(data[4480]) != 0;
        migratorPayload = data[4481:5569];
    }

    /// @dev Decodes the changeTransactionKey payload.
    ///      Layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig.
    /// @param payload The packed changeTransactionKey payload (2272 bytes).
    function decodeChangeTransactionKey(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        assembly {
            currentKey := payload.offset
            nextKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
        }
    }

    /// @dev Decodes the ERC-4337 UserOp signature payload.
    ///      Layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig.
    /// @param sig The UserOp signature bytes.
    function decodeUserOpSignature(
        bytes calldata sig
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        assembly {
            currentKey := sig.offset
            nextKey := add(sig.offset, 64)
            pqSig := add(sig.offset, 128)
        }
    }

    /// @dev Decodes the execute payload.
    ///      Layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig,
    ///              [2272:2304) target, [2304:2336) value, [2336:...) data.
    /// @param payload The packed execute payload (>= 2336 bytes).
    function decodeExecute(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            address target,
            uint256 value,
            bytes calldata data
        )
    {
        assembly {
            currentKey := payload.offset
            nextKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
            target := calldataload(add(payload.offset, 2272))
            value := calldataload(add(payload.offset, 2304))
        }
        data = payload[2336:];
    }

    /// @dev Decodes the withdrawDeposit payload.
    ///      Layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig,
    ///              [2272:2304) to, [2304:2336) amount.
    /// @param payload The packed withdrawDeposit payload (2336 bytes).
    function decodeWithdrawDeposit(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            address to,
            uint256 amount
        )
    {
        assembly {
            currentKey := payload.offset
            nextKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
            to := calldataload(add(payload.offset, 2272))
            amount := calldataload(add(payload.offset, 2304))
        }
    }

    /// @dev Decodes the recoverWallet payload.
    ///      Layout: [0:64) recoveryKey, [64:128) newTransactionKey, [128:2272) pqSig.
    /// @param payload The packed recoverWallet payload (2272 bytes).
    function decodeRecoverWallet(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata recoveryKey,
            WOTSPlus.WinternitzAddress calldata newTransactionKey,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        assembly {
            recoveryKey := payload.offset
            newTransactionKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
        }
    }

    /// @dev Decodes a keyManagement-style payload (kind, currentKey, nextKey, pqSig, keys[]).
    ///      Layout: [0:32) kind, [32:96) currentKey, [96:160) nextKey, [160:2304) pqSig,
    ///              [2304:...) keys.
    ///      The `kind` field is encoded as a left-padded uint256; decoding implicitly validates
    ///      the range via the enum cast (reverts on out-of-range).
    /// @param payload The packed keyManagement payload (>= 2304 bytes).
    function decodeKeyManagement(
        bytes calldata payload
    )
        internal
        pure
        returns (
            KeyType kind,
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata keys
        )
    {
        uint256 raw;
        assembly {
            raw := calldataload(payload.offset)
            currentKey := add(payload.offset, 32)
            nextKey := add(payload.offset, 96)
            pqSig := add(payload.offset, 160)
            keys.offset := add(payload.offset, 2304)
            keys.length := div(sub(payload.length, 2304), 64)
        }
        kind = KeyType(raw);
    }

    /// @dev Decodes the transferOwnership / completeOwnershipHandover payload.
    ///      The call is a full re-initialization: the caller hands the wallet to a new
    ///      classical owner along with a fresh set of PQ key material that the new owner
    ///      alone controls. The existing `ownershipKey` authorizes the whole bundle and
    ///      rotates on use.
    ///      Layout: [0:64) currentOwnershipKey, [64:128) newOwnershipKey,
    ///              [128:2272) pqSig, [2272:2304) newOwner,
    ///              [2304:2368) newDisasterKey, [2368:2688) newTransactionKeys[5],
    ///              [2688:3328) newRecoveryKeys[10].
    /// @param payload The packed ownership-transfer payload (3328 bytes).
    function decodeOwnershipTransfer(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentOwnershipKey,
            WOTSPlus.WinternitzAddress calldata newOwnershipKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            address newOwner,
            WOTSPlus.WinternitzAddress calldata newDisasterKey,
            WOTSPlus.WinternitzAddress[5] calldata newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata newRecoveryKeys
        )
    {
        assembly {
            currentOwnershipKey := payload.offset
            newOwnershipKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
            newOwner := calldataload(add(payload.offset, 2272))
            newDisasterKey := add(payload.offset, 2304)
            newTransactionKeys := add(payload.offset, 2368)
            newRecoveryKeys := add(payload.offset, 2688)
        }
    }

    /// @dev Decodes the replaceVerificationKeyAt payload.
    ///      Layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig,
    ///              [2272:2304) index, [2304:2368) newKey.
    function decodeVerificationKeysReplace(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            uint256 index,
            WOTSPlus.WinternitzAddress calldata newKey
        )
    {
        assembly {
            currentKey := payload.offset
            nextKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
            index := calldataload(add(payload.offset, 2272))
            newKey := add(payload.offset, 2304)
        }
    }

    /// @dev Decodes the ERC-1271 signature payload.
    ///      Layout: [0:64) verifier, [64:2208) pqSig, [2208:2273) ecdsaSig (r ++ s ++ v).
    ///      The ECDSA half is a standard 65-byte secp256k1 signature over the raw
    ///      ERC-1271 hash (no domain tag) — it is an AND-mode failsafe on top of the
    ///      WOTS+ half, recovered against the wallet's classical `owner()`.
    function decodeErc1271Signature(
        bytes calldata signature
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata verifier,
            WOTSPlus.WinternitzElements calldata pqSig,
            bytes calldata ecdsaSig
        )
    {
        assembly {
            verifier := signature.offset
            pqSig := add(signature.offset, 64)
        }
        ecdsaSig = signature[2208:2273];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ENCODERS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Encodes the saveWallet payload.
    /// @return The packed payload (3232 bytes).
    function encodeSaveWallet(
        WOTSPlus.WinternitzAddress memory currentDisasterKey,
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[5] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(
            currentDisasterKey.publicSeed,
            currentDisasterKey.publicKeyHash,
            newDisasterKey.publicSeed,
            newDisasterKey.publicKeyHash,
            pqSig.elements
        );
        for (uint256 i = 0; i < TRANSACTION_KEY_INIT_AMOUNT; i++) {
            payload = abi.encodePacked(
                payload,
                newTransactionKeys[i].publicSeed,
                newTransactionKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < RECOVERY_KEY_AMOUNT; i++) {
            payload = abi.encodePacked(
                payload,
                newRecoveryKeys[i].publicSeed,
                newRecoveryKeys[i].publicKeyHash
            );
        }
        return payload;
    }

    /// @dev Encodes the init payload.
    /// @return The packed payload (1088 bytes).
    function encodeInit(
        WOTSPlus.WinternitzAddress memory disasterRecoveryKey,
        WOTSPlus.WinternitzAddress memory ownershipKey,
        WOTSPlus.WinternitzAddress[5] memory transactionKeys,
        WOTSPlus.WinternitzAddress[10] memory recoveryKeys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(
            disasterRecoveryKey.publicSeed,
            disasterRecoveryKey.publicKeyHash,
            ownershipKey.publicSeed,
            ownershipKey.publicKeyHash
        );
        for (uint256 i = 0; i < TRANSACTION_KEY_INIT_AMOUNT; i++) {
            payload = abi.encodePacked(
                payload,
                transactionKeys[i].publicSeed,
                transactionKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < RECOVERY_KEY_AMOUNT; i++) {
            payload = abi.encodePacked(
                payload,
                recoveryKeys[i].publicSeed,
                recoveryKeys[i].publicKeyHash
            );
        }
        return payload;
    }

    /// @dev Encodes the changeTransactionKey payload.
    /// @return The packed payload (2272 bytes).
    function encodeChangeTransactionKey(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                currentKey.publicSeed,
                currentKey.publicKeyHash,
                nextKey.publicSeed,
                nextKey.publicKeyHash,
                pqSig.elements
            );
    }

    /// @dev Encodes the execute payload.
    /// @return The packed payload (>= 2336 bytes).
    function encodeExecute(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address target,
        uint256 value,
        bytes memory data
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                currentKey.publicSeed,
                currentKey.publicKeyHash,
                nextKey.publicSeed,
                nextKey.publicKeyHash,
                pqSig.elements,
                bytes32(uint256(uint160(target))),
                value,
                data
            );
    }

    /// @dev Encodes the recoverWallet payload.
    /// @return The packed payload (2272 bytes).
    function encodeRecoverWallet(
        WOTSPlus.WinternitzAddress memory recoveryKey,
        WOTSPlus.WinternitzAddress memory newTransactionKey,
        WOTSPlus.WinternitzElements memory pqSig
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                recoveryKey.publicSeed,
                recoveryKey.publicKeyHash,
                newTransactionKey.publicSeed,
                newTransactionKey.publicKeyHash,
                pqSig.elements
            );
    }

    /// @dev Encodes a keyManagement-style payload.
    /// @return The packed payload (2304 + N*64 bytes).
    function encodeKeyManagement(
        KeyType kind,
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[] memory keys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(kind)),
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            pqSig.elements
        );
        for (uint256 i = 0; i < keys.length; i++) {
            payload = abi.encodePacked(
                payload,
                keys[i].publicSeed,
                keys[i].publicKeyHash
            );
        }
        return payload;
    }

    /// @dev Encodes the ERC-4337 UserOp signature payload.
    /// @return The packed signature (2272 bytes).
    function encodeUserOpSignature(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                currentKey.publicSeed,
                currentKey.publicKeyHash,
                nextKey.publicSeed,
                nextKey.publicKeyHash,
                pqSig.elements
            );
    }

    /// @dev Encodes the withdrawDeposit payload.
    /// @return The packed payload (2336 bytes).
    function encodeWithdrawDeposit(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address to,
        uint256 amount
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                currentKey.publicSeed,
                currentKey.publicKeyHash,
                nextKey.publicSeed,
                nextKey.publicKeyHash,
                pqSig.elements,
                bytes32(uint256(uint160(to))),
                amount
            );
    }

    /// @dev Encodes the transferOwnership / completeOwnershipHandover payload.
    /// @return The packed payload (3328 bytes).
    function encodeOwnershipTransfer(
        WOTSPlus.WinternitzAddress memory currentOwnershipKey,
        WOTSPlus.WinternitzAddress memory newOwnershipKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address newOwner,
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzAddress[5] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(
            currentOwnershipKey.publicSeed,
            currentOwnershipKey.publicKeyHash,
            newOwnershipKey.publicSeed,
            newOwnershipKey.publicKeyHash,
            pqSig.elements,
            bytes32(uint256(uint160(newOwner))),
            newDisasterKey.publicSeed,
            newDisasterKey.publicKeyHash
        );
        for (uint256 i = 0; i < TRANSACTION_KEY_INIT_AMOUNT; i++) {
            payload = abi.encodePacked(
                payload,
                newTransactionKeys[i].publicSeed,
                newTransactionKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < RECOVERY_KEY_AMOUNT; i++) {
            payload = abi.encodePacked(
                payload,
                newRecoveryKeys[i].publicSeed,
                newRecoveryKeys[i].publicKeyHash
            );
        }
        return payload;
    }

    /// @dev Encodes the replaceVerificationKeyAt payload.
    /// @return The packed payload (2368 bytes).
    function encodeVerificationKeysReplace(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        uint256 index,
        WOTSPlus.WinternitzAddress memory newKey
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                currentKey.publicSeed,
                currentKey.publicKeyHash,
                nextKey.publicSeed,
                nextKey.publicKeyHash,
                pqSig.elements,
                bytes32(index),
                newKey.publicSeed,
                newKey.publicKeyHash
            );
    }

    /// @dev Encodes the ERC-1271 signature payload.
    /// @param ecdsaSig Standard 65-byte secp256k1 signature (r ++ s ++ v).
    /// @return The packed signature (2273 bytes).
    function encodeErc1271Signature(
        WOTSPlus.WinternitzAddress memory verifier,
        WOTSPlus.WinternitzElements memory pqSig,
        bytes memory ecdsaSig
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                verifier.publicSeed,
                verifier.publicKeyHash,
                pqSig.elements,
                ecdsaSig
            );
    }

    /// @dev Encodes the recoveryUpgrade payload (auth + verification portions).
    /// @return The packed payload (4416 bytes).
    function encodeRecoveryUpgrade(
        WOTSPlus.WinternitzAddress memory recoveryKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress memory verifier,
        WOTSPlus.WinternitzElements memory verifySig
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                recoveryKey.publicSeed,
                recoveryKey.publicKeyHash,
                pqSig.elements,
                verifier.publicSeed,
                verifier.publicKeyHash,
                verifySig.elements
            );
    }

    /// @dev Encodes the full upgradeToAndCall payload (auth + verification + migration).
    /// @return The packed payload (5505 bytes).
    function encodeUpgradeToAndCall(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress memory verifier,
        WOTSPlus.WinternitzElements memory verifySig,
        bool shouldMigrate,
        bytes memory migratorPayload
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                currentKey.publicSeed,
                currentKey.publicKeyHash,
                nextKey.publicSeed,
                nextKey.publicKeyHash,
                pqSig.elements,
                verifier.publicSeed,
                verifier.publicKeyHash,
                verifySig.elements,
                uint8(shouldMigrate ? 1 : 0),
                migratorPayload
            );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          HASHERS                              */
    /*  NOTE: WOTS+ signatures are incompatible with EIP-712. These  */
    /*  digests use domain tags instead of EIP-712 structured data.  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev keccak256(abi.encode(KEY_ROTATION_TAG, chainId, wallet, s1, h1, s2, h2))
    ///      Used by changeTransactionKey and recoverWallet.
    function keyRotationDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                KEY_ROTATION_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                s1,
                h1,
                s2,
                h2
            );
    }

    /// @dev keccak256(abi.encode(EXECUTE_TAG, chainId, wallet, s1, h1, s2, h2, target, value, opdataHash, fee))
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
        return
            EfficientHashLib.hash(
                EXECUTE_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                s1,
                h1,
                s2,
                h2,
                bytes32(uint256(uint160(target))),
                bytes32(value),
                opdataHash,
                bytes32(fee)
            );
    }

    /// @dev keccak256(abi.encode(WITHDRAW_DEPOSIT_TAG, chainId, wallet, s1, h1, s2, h2, to, amount))
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
        return
            EfficientHashLib.hash(
                WITHDRAW_DEPOSIT_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                s1,
                h1,
                s2,
                h2,
                bytes32(uint256(uint160(to))),
                bytes32(amount)
            );
    }

    /// @dev Returns the digest that `addKeys` / `refreshKeys` sign over. The domain
    ///      tag is selected per `kind` so a signature authorizing one keyset cannot
    ///      be replayed against another. Equivalent to:
    ///        keccak256(abi.encode(tag(kind), chainId, wallet, s1, h1, s2, h2, keysHash))
    ///      where `tag` maps Transaction → `ADD_TRANSACTION_KEYS_TAG`,
    ///      Verification → `VERIFICATION_KEYS_TAG`, Recovery → `KEY_MGMT_TAG`.
    function keysetDigest(
        KeyType kind,
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 keysHash
    ) internal pure returns (bytes32) {
        bytes32 tag = kind == KeyType.Transaction
            ? ADD_TRANSACTION_KEYS_TAG
            : kind == KeyType.Verification
                ? VERIFICATION_KEYS_TAG
                : KEY_MGMT_TAG;
        return
            EfficientHashLib.hash(
                tag,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                s1,
                h1,
                s2,
                h2,
                keysHash
            );
    }

    /// @dev keccak256(abi.encode(UPGRADE_TAG, chainId, wallet, newImpl, s1, h1, s2, h2))
    function upgradeDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                UPGRADE_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                bytes32(uint256(uint160(newImplementation))),
                s1,
                h1,
                s2,
                h2
            );
    }

    /// @dev keccak256(abi.encode(VERIFICATION_TAG, chainId, wallet, newImpl, s1, h1))
    function verificationDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                VERIFICATION_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                bytes32(uint256(uint160(newImplementation))),
                s1,
                h1
            );
    }

    /// @dev keccak256(abi.encode(ERC4337_EXECUTE_TAG, chainId, wallet, s1, h1, s2, h2, userOpHash, fee))
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
        return
            EfficientHashLib.hash(
                ERC4337_EXECUTE_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                s1,
                h1,
                s2,
                h2,
                userOpHash,
                bytes32(fee)
            );
    }

    /// @dev keccak256(abi.encode(UPGRADE_RECOVERY_TAG, chainId, wallet, newImpl, recoverySeed, recoveryHash))
    ///      Used by recoveryUpgrade. Binds chain/wallet/newImpl/recoveryKey only — no
    ///      transaction-key fields are mixed in because recoveryUpgrade does not rotate.
    function upgradeRecoveryDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 recoverySeed,
        bytes32 recoveryHash
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                UPGRADE_RECOVERY_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                bytes32(uint256(uint160(newImplementation))),
                recoverySeed,
                recoveryHash
            );
    }

    /// @dev keccak256(abi.encode(TRANSFER_OWNERSHIP_TAG, chainId, wallet, s1, h1, s2, h2,
    ///                           newOwner, keysHash))
    ///      where `keysHash = keccak256(abi.encode(newDisasterKey, newTransactionKeys,
    ///      newRecoveryKeys))`. The ownership-transfer digest commits to the entire
    ///      re-initialization bundle so the WOTS+ signature cannot be separated from
    ///      the key material it installs.
    function transferOwnershipDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address newOwner,
        bytes32 keysHash
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                TRANSFER_OWNERSHIP_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                s1,
                h1,
                s2,
                h2,
                bytes32(uint256(uint160(newOwner))),
                keysHash
            );
    }

    /// @dev keccak256(abi.encode(COMPLETE_OWNERSHIP_HANDOVER_TAG, chainId, wallet, s1, h1, s2,
    ///                           h2, pendingOwner, keysHash))
    ///      where `keysHash = keccak256(abi.encode(newDisasterKey, newTransactionKeys,
    ///      newRecoveryKeys))`.
    function completeOwnershipHandoverDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address pendingOwner,
        bytes32 keysHash
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                COMPLETE_OWNERSHIP_HANDOVER_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                s1,
                h1,
                s2,
                h2,
                bytes32(uint256(uint160(pendingOwner))),
                keysHash
            );
    }

    /// @dev keccak256(abi.encode(VERIFICATION_KEYS_REPLACE_TAG, chainId, wallet, s1, h1, s2, h2, index, newSeed, newHash))
    function verificationKeysReplaceDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        uint256 index,
        bytes32 newSeed,
        bytes32 newHash
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                VERIFICATION_KEYS_REPLACE_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                s1,
                h1,
                s2,
                h2,
                bytes32(index),
                newSeed,
                newHash
            );
    }

    /// @dev keccak256(abi.encode(ERC1271_TAG, chainId, wallet, verifierSeed, verifierHash, messageHash))
    function erc1271Digest(
        address wallet,
        uint256 chainId,
        bytes32 verifierSeed,
        bytes32 verifierHash,
        bytes32 messageHash
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                ERC1271_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                verifierSeed,
                verifierHash,
                messageHash
            );
    }

    /// @dev keccak256(abi.encode(SAVE_WALLET_TAG, chainId, wallet, currentSeed,
    ///                           currentHash, newSeed, newHash, keysHash))
    ///      where `keysHash = keccak256(abi.encode(newTransactionKeys, newRecoveryKeys))`.
    function saveWalletDigest(
        address wallet,
        uint256 chainId,
        bytes32 currentSeed,
        bytes32 currentHash,
        bytes32 newSeed,
        bytes32 newHash,
        bytes32 keysHash
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                SAVE_WALLET_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                currentSeed,
                currentHash,
                newSeed,
                newHash,
                keysHash
            );
    }
}
