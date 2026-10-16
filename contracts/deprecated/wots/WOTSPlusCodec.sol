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

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

/// @title WOTSPlusCodec
/// @dev All guarded operations carry an explicit (currentKey, nextKey) pair up front,
///      naming the transaction key being consumed and the replacement being installed.
///
///      Init payload layout (2048 bytes, used by initialize & migrate):
///      [0:64)      WinternitzAddress     — disasterRecoveryKey
///      [64:128)    WinternitzAddress     — ownershipKey
///      [128:768)   WinternitzAddress[10] — transactionKeys (10 x 64)
///      [768:1408)  WinternitzAddress[10] — recoveryKeys (10 x 64)
///      [1408:2048) WinternitzAddress[10] — verificationKeys (10 x 64)
///
///      upgradeToAndCall payload layout (6529 bytes):
///      [0:64)      WinternitzAddress     — currentKey (publicSeed ++ publicKeyHash)
///      [64:128)    WinternitzAddress     — nextKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///      [2272:2336) WinternitzAddress     — verifier
///      [2336:4480) WinternitzElements    — verifySig (67 x 32)
///      [4480]      uint8                 — shouldMigrate (0x00 = false, 0x01 = true)
///      [4481:6529) bytes                 — migratorPayload (init layout, 2048 bytes)
///
///      recoveryUpgrade payload layout (4480 bytes):
///      [0:64)      WinternitzAddress     — currentRecoveryKey
///                                          (consumed, replaced by newRecoveryKey)
///      [64:128)    WinternitzAddress     — newRecoveryKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///      [2272:2336) WinternitzAddress     — verifier
///      [2336:4480) WinternitzElements    — verifySig (67 x 32)
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
///      saveWallet payload layout (4192 bytes):
///      [0:64)      WinternitzAddress     — currentDisasterKey
///      [64:128)    WinternitzAddress     — newDisasterKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///      [2272:2912) WinternitzAddress[10] — newTransactionKeys (10 x 64)
///      [2912:3552) WinternitzAddress[10] — newRecoveryKeys (10 x 64)
///      [3552:4192) WinternitzAddress[10] — newVerificationKeys (10 x 64)
///
///      ownershipTransfer payload layout (4288 bytes, used by transferOwnership and
///      completeOwnershipHandover):
///      [0:64)      WinternitzAddress     — currentOwnershipKey
///      [64:128)    WinternitzAddress     — newOwnershipKey
///      [128:2272)  WinternitzElements    — pqSig (67 x 32)
///      [2272:2304) bytes32               — newOwner (left-padded address)
///      [2304:2368) WinternitzAddress     — newDisasterKey
///      [2368:3008) WinternitzAddress[10] — newTransactionKeys (10 x 64)
///      [3008:3648) WinternitzAddress[10] — newRecoveryKeys (10 x 64)
///      [3648:4288) WinternitzAddress[10] — newVerificationKeys (10 x 64)
///
///      replaceKeys payload layout (2368 + 2*N*64 bytes, variable-length):
///      [0:32)      uint256               — kind (KeyType: target keyset)
///      [32:64)     uint256               — signingKind (KeyType: Tx or Recovery)
///      [64:96)     uint256               — n (length of each key array)
///      [96:160)    WinternitzAddress     — currentKey (auth; in signingKind set)
///      [160:224)   WinternitzAddress     — nextKey (replacement in signingKind set)
///      [224:2368)  WinternitzElements    — pqSig (67 x 32)
///      [2368:...)  WinternitzAddress[]   — oldKeys (n x 64)
///      [...]       WinternitzAddress[]   — newKeys (n x 64)
///
///      resetKeyset payload layout (2976 bytes, fixed):
///      [0:32)      uint256               — kind (KeyType: target keyset)
///      [32:64)     uint256               — signingKind (KeyType: Tx or Recovery)
///      [64:128)    WinternitzAddress     — currentKey (auth; in signingKind set)
///      [128:192)   WinternitzAddress     — nextKey (replacement in signingKind set)
///      [192:2336)  WinternitzElements    — pqSig (67 x 32)
///      [2336:2976) WinternitzAddress[10] — newKeys (10 x 64)
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
///        MAX_KEYS = 10  (every keyset always holds exactly 10 entries)
/// @custom:deprecated The WOTS+ wallet family is sunset — superseded by SHRINCS
///                    (contracts/shrincs/). Kept fully functional for existing deployments.
library WOTSPlusCodec {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ERRORS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when a decoder is invoked with a payload whose length does
    ///         not match the layout it expects. For variable-length decoders
    ///         (`decodeExecute`, `decodeReplaceKeys`), `expected` is either the
    ///         minimum required size (when the actual length falls below it) or
    ///         the exact size implied by the variable-length field (when the
    ///         payload's stride and that field disagree).
    /// @param expected The exact (or minimum) size the decoder requires.
    /// @param actual The actual length of the payload provided.
    error MalformedPayload(uint256 expected, uint256 actual);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         TYPES                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Discriminator for the three PQ keysets managed by a WOTSPlusImplementation.
    /// @dev Travels at the head of every keyset-management payload
    ///      (`replaceKeys`, `resetKeyset`) and selects the target keyset.
    ///      The enum cast performed by the decoders implicitly validates that
    ///      the on-wire value falls within `[0, 2]` (reverts via Solidity 0.8
    ///      panic otherwise).
    enum KeyType {
        Transaction,
        Recovery,
        Verification
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CONSTANTS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Every keyset (`transactionKeys`, `recoveryKeys`, `verificationKeys`)
    ///      holds exactly this many entries at every state-transition boundary
    ///      (`initialize`, `migrate`, `saveWallet`, `transferOwnership`,
    ///      `resetKeyset`). `replaceKeys` swaps N-for-N within this fixed size.
    uint256 internal constant MAX_KEYS = 10;

    /// @dev 160-bit mask applied to addresses decoded out of raw calldata
    ///      words via `calldataload`. The packed-payload encoders right-align
    ///      addresses with 12 zero bytes of left-padding, so on legitimate
    ///      calldata the upper 96 bits are already zero. Masking is defence
    ///      in depth: it guarantees any future code path that hashes or
    ///      passes the address into further raw assembly sees a canonical
    ///      value, regardless of what the caller stuffed into the upper
    ///      bits of the 32-byte slot.
    // The leading `00` is solc's documented workaround so a 20-byte hex
    // literal isn't mistaken for an address. The numeric value is exactly
    // `type(uint160).max` (160 ones); inline assembly only accepts direct
    // number literals as constant references, not the `type(...)` form,
    // so the literal form is used here.
    uint256 internal constant _ADDRESS_MASK =
        0x00ffffffffffffffffffffffffffffffffffffffff;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      DOMAIN TAGS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Every digest committed to a WOTS+ signature is prefixed with a unique
    // domain tag. The tag is the first preimage element fed into
    // `EfficientHashLib.hash(...)` alongside chainId, wallet, and the
    // operation-specific fields. Each tag binds a signature to exactly one
    // operation shape so a signature produced for one code path cannot be
    // lifted and replayed against another.
    //
    bytes32 internal constant EXECUTE_TAG = keccak256("quip.digest.execute");
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
    /// @dev Per-(signingKind, targetKind) domain tags for `replaceKeysDigest`.
    ///      Six tags = 2 signing keysets × 3 target keysets. Distinct tags
    ///      prevent lifting a `replaceKeys` signature across either axis:
    ///      a tx-signed replacement on the recovery keyset cannot be replayed
    ///      against a tx-signed replacement on the verification keyset, nor
    ///      against a recovery-signed replacement on any target. The signing
    ///      keyset is restricted to {Transaction, Recovery} at the wallet
    ///      level (verification keys are not signing-capable).
    bytes32 internal constant REPLACE_KEYS_TXSIGN_TX_TAG =
        keccak256("quip.digest.replaceKeys.txSign.tx");
    bytes32 internal constant REPLACE_KEYS_TXSIGN_RECOVERY_TAG =
        keccak256("quip.digest.replaceKeys.txSign.recovery");
    bytes32 internal constant REPLACE_KEYS_TXSIGN_VERIFY_TAG =
        keccak256("quip.digest.replaceKeys.txSign.verification");
    bytes32 internal constant REPLACE_KEYS_RECSIGN_TX_TAG =
        keccak256("quip.digest.replaceKeys.recoverySign.tx");
    bytes32 internal constant REPLACE_KEYS_RECSIGN_RECOVERY_TAG =
        keccak256("quip.digest.replaceKeys.recoverySign.recovery");
    bytes32 internal constant REPLACE_KEYS_RECSIGN_VERIFY_TAG =
        keccak256("quip.digest.replaceKeys.recoverySign.verification");
    /// @dev Per-(signingKind, targetKind) domain tags for `resetKeysetDigest`.
    ///      Mirrors the `REPLACE_KEYS_*` taxonomy — six tags = 2 signing keysets
    ///      × 3 target keysets. Distinct tags prevent lifting a `resetKeyset`
    ///      signature across either axis: a tx-signed reset of the recovery
    ///      keyset cannot be replayed against a tx-signed reset of the
    ///      verification keyset, nor against a recovery-signed reset on any
    ///      target. The signing keyset is restricted to {Transaction, Recovery}
    ///      at the wallet level (verification keys are not signing-capable).
    bytes32 internal constant RESET_KEYSET_TXSIGN_TX_TAG =
        keccak256("quip.digest.resetKeyset.txSign.tx");
    bytes32 internal constant RESET_KEYSET_TXSIGN_RECOVERY_TAG =
        keccak256("quip.digest.resetKeyset.txSign.recovery");
    bytes32 internal constant RESET_KEYSET_TXSIGN_VERIFY_TAG =
        keccak256("quip.digest.resetKeyset.txSign.verification");
    bytes32 internal constant RESET_KEYSET_RECSIGN_TX_TAG =
        keccak256("quip.digest.resetKeyset.recoverySign.tx");
    bytes32 internal constant RESET_KEYSET_RECSIGN_RECOVERY_TAG =
        keccak256("quip.digest.resetKeyset.recoverySign.recovery");
    bytes32 internal constant RESET_KEYSET_RECSIGN_VERIFY_TAG =
        keccak256("quip.digest.resetKeyset.recoverySign.verification");
    bytes32 internal constant ERC1271_TAG = keccak256("quip.digest.erc1271");
    /// @dev Disaster-recovery domain tag. Used by `saveWalletDigest` to bind a
    ///      `saveWallet` signature to a specific wallet, chain, and key-rotation pair.
    bytes32 internal constant SAVE_WALLET_TAG =
        keccak256("quip.digest.saveWallet");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        DECODERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Decodes the init payload into disaster recovery key, ownership key, transaction
    ///      keys, recovery keys, and verification keys.
    ///      Layout: [0:64) disasterRecoveryKey, [64:128) ownershipKey,
    ///              [128:768) transactionKeys[10], [768:1408) recoveryKeys[10],
    ///              [1408:2048) verificationKeys[10].
    ///      Used by initialize() and migrate().
    /// @param payload The packed init or migrator payload (2048 bytes).
    /// @return disasterRecoveryKey The last-resort WOTS+ rescue key at offset 0.
    /// @return ownershipKey The ownership-transfer WOTS+ key at offset 64.
    /// @return transactionKeys The 10 initial transaction keys at offset 128.
    /// @return recoveryKeys The 10 recovery keys at offset 768.
    /// @return verificationKeys The 10 verification keys at offset 1408.
    function decodeInit(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata disasterRecoveryKey,
            WOTSPlus.WinternitzAddress calldata ownershipKey,
            WOTSPlus.WinternitzAddress[10] calldata transactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata recoveryKeys,
            WOTSPlus.WinternitzAddress[10] calldata verificationKeys
        )
    {
        if (payload.length != 2048) {
            revert MalformedPayload(2048, payload.length);
        }
        assembly {
            disasterRecoveryKey := payload.offset
            ownershipKey := add(payload.offset, 64)
            transactionKeys := add(payload.offset, 128)
            recoveryKeys := add(payload.offset, 768)
            verificationKeys := add(payload.offset, 1408)
        }
    }

    /// @dev Decodes the saveWallet payload.
    ///      Layout: [0:64) currentDisasterKey, [64:128) newDisasterKey,
    ///              [128:2272) pqSig, [2272:2912) newTransactionKeys[10],
    ///              [2912:3552) newRecoveryKeys[10],
    ///              [3552:4192) newVerificationKeys[10].
    /// @param payload The packed saveWallet payload (4192 bytes).
    function decodeSaveWallet(
        bytes calldata payload
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentDisasterKey,
            WOTSPlus.WinternitzAddress calldata newDisasterKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[10] calldata newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata newRecoveryKeys,
            WOTSPlus.WinternitzAddress[10] calldata newVerificationKeys
        )
    {
        if (payload.length != 4192) {
            revert MalformedPayload(4192, payload.length);
        }
        assembly {
            currentDisasterKey := payload.offset
            newDisasterKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
            newTransactionKeys := add(payload.offset, 2272)
            newRecoveryKeys := add(payload.offset, 2912)
            newVerificationKeys := add(payload.offset, 3552)
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
        // The full upgrade payload is shared between auth/verification/migration
        // decoders, so the length precondition is the full 6529 bytes.
        if (data.length != 6529) revert MalformedPayload(6529, data.length);
        assembly {
            currentKey := data.offset
            nextKey := add(data.offset, 64)
            pqSig := add(data.offset, 128)
        }
    }

    /// @dev Decodes the recoveryUpgrade payload's authentication portion.
    ///      Layout: [0:64) currentRecoveryKey, [64:128) newRecoveryKey,
    ///              [128:2272) pqSig.
    ///      The current recovery key is consumed and replaced in-place by
    ///      `newRecoveryKey` so the recovery keyset size stays stable.
    /// @param data The packed recoveryUpgrade payload (4480 bytes).
    /// @return currentRecoveryKey The consumed recovery key at offset 0.
    /// @return newRecoveryKey The replacement recovery key at offset 64.
    /// @return pqSig The PQ signature at offset 128.
    function decodeRecoveryUpgradeAuth(
        bytes calldata data
    )
        internal
        pure
        returns (
            WOTSPlus.WinternitzAddress calldata currentRecoveryKey,
            WOTSPlus.WinternitzAddress calldata newRecoveryKey,
            WOTSPlus.WinternitzElements calldata pqSig
        )
    {
        // The full recoveryUpgrade payload is shared between auth and verification
        // decoders, so the length precondition is the full 4480 bytes.
        if (data.length != 4480) revert MalformedPayload(4480, data.length);
        assembly {
            currentRecoveryKey := data.offset
            newRecoveryKey := add(data.offset, 64)
            pqSig := add(data.offset, 128)
        }
    }

    /// @dev Decodes the upgradeToAndCall payload's verification portion.
    ///      Layout: [2272:2336) verifier, [2336:4480) verifySig.
    ///      Used by verifyUpgrade() in the upgradeToAndCall path.
    /// @param data The packed upgrade payload (6529 bytes).
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
        // Operates on the full 6529-byte upgrade payload (shared with auth/migration).
        if (data.length != 6529) revert MalformedPayload(6529, data.length);
        assembly {
            verifier := add(data.offset, 2272)
            verifySig := add(data.offset, 2336)
        }
    }

    /// @dev Decodes the recoveryUpgrade payload's verification portion.
    ///      Layout: [2272:2336) verifier, [2336:4480) verifySig.
    /// @param data The packed recoveryUpgrade payload (4480 bytes).
    /// @return verifier The verifier's WinternitzAddress at offset 2272.
    /// @return verifySig The verifier's WinternitzElements at offset 2336.
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
        // Operates on the full 4480-byte recoveryUpgrade payload (shared with auth).
        if (data.length != 4480) revert MalformedPayload(4480, data.length);
        assembly {
            verifier := add(data.offset, 2272)
            verifySig := add(data.offset, 2336)
        }
    }

    /// @dev Decodes the upgradeToAndCall payload's migration portion.
    ///      Layout: [4480] shouldMigrate, [4481:6529) migratorPayload.
    /// @param data The packed upgrade payload (6529 bytes).
    /// @return shouldMigrate True if state migration is required.
    /// @return migratorPayload The 2048-byte init-layout payload for the new implementation.
    function decodeUpgradeMigration(
        bytes calldata data
    )
        internal
        pure
        returns (bool shouldMigrate, bytes calldata migratorPayload)
    {
        // Solidity indexing on the body below would already bounds-check, but
        // raise an explicit MalformedPayload for codec-wide uniformity.
        if (data.length != 6529) revert MalformedPayload(6529, data.length);
        // The on-wire contract is "0x00 = false, 0x01 = true" — strictly
        // reject 0x02..0xff so an off-chain encoder bug can't smuggle
        // shouldMigrate=true via an undefined byte value. `MalformedPayload`
        // is reused here with (1, badByte) interpreted as "expected ≤ 1, got
        // badByte" to keep the codec-wide error API uniform.
        uint8 b = uint8(data[4480]);
        if (b > 1) revert MalformedPayload(1, b);
        shouldMigrate = b == 1;
        migratorPayload = data[4481:6529];
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
        if (sig.length != 2272) {
            revert MalformedPayload(2272, sig.length);
        }
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
        // Variable-length: header is 2336 bytes; the trailing `data` slice may be
        // empty (length == 2336) or arbitrarily long.
        if (payload.length < 2336) {
            revert MalformedPayload(2336, payload.length);
        }
        assembly {
            currentKey := payload.offset
            nextKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
            // Mask the upper 96 bits — see `_ADDRESS_MASK` doc.
            target := and(
                calldataload(add(payload.offset, 2272)),
                _ADDRESS_MASK
            )
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
        if (payload.length != 2336) {
            revert MalformedPayload(2336, payload.length);
        }
        assembly {
            currentKey := payload.offset
            nextKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
            // Mask the upper 96 bits — see `_ADDRESS_MASK` doc.
            to := and(calldataload(add(payload.offset, 2272)), _ADDRESS_MASK)
            amount := calldataload(add(payload.offset, 2304))
        }
    }

    /// @dev Decodes the transferOwnership / completeOwnershipHandover payload.
    ///      The call is a full re-initialization: the caller hands the wallet to a new
    ///      classical owner along with a fresh set of PQ key material that the new owner
    ///      alone controls. The existing `ownershipKey` authorizes the whole bundle and
    ///      rotates on use.
    ///      Layout: [0:64) currentOwnershipKey, [64:128) newOwnershipKey,
    ///              [128:2272) pqSig, [2272:2304) newOwner,
    ///              [2304:2368) newDisasterKey, [2368:3008) newTransactionKeys[10],
    ///              [3008:3648) newRecoveryKeys[10], [3648:4288) newVerificationKeys[10].
    /// @param payload The packed ownership-transfer payload (4288 bytes).
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
            WOTSPlus.WinternitzAddress[10] calldata newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] calldata newRecoveryKeys,
            WOTSPlus.WinternitzAddress[10] calldata newVerificationKeys
        )
    {
        if (payload.length != 4288) {
            revert MalformedPayload(4288, payload.length);
        }
        assembly {
            currentOwnershipKey := payload.offset
            newOwnershipKey := add(payload.offset, 64)
            pqSig := add(payload.offset, 128)
            // Mask the upper 96 bits — see `_ADDRESS_MASK` doc.
            newOwner := and(
                calldataload(add(payload.offset, 2272)),
                _ADDRESS_MASK
            )
            newDisasterKey := add(payload.offset, 2304)
            newTransactionKeys := add(payload.offset, 2368)
            newRecoveryKeys := add(payload.offset, 3008)
            newVerificationKeys := add(payload.offset, 3648)
        }
    }

    /// @dev Decodes the replaceKeys payload.
    ///      Layout: [0:32) kind, [32:64) signingKind, [64:96) n,
    ///              [96:160) currentKey, [160:224) nextKey,
    ///              [224:2368) pqSig, [2368:2368+n*64) oldKeys,
    ///              [2368+n*64:2368+2*n*64) newKeys.
    ///      Both `kind` and `signingKind` are encoded as left-padded uint256s;
    ///      the enum cast implicitly validates the range via Solidity 0.8 panic.
    ///      The explicit `n` enables a strict length check: the caller-supplied
    ///      array stride must produce a payload exactly `2368 + 2*n*64` bytes
    ///      long, catching truncation, garbage suffixes, and length/stride
    ///      mismatches at the decode boundary.
    ///      Assembly is split into small blocks because the Solidity stack
    ///      budget for inline asm runs out if every calldata-ref assignment
    ///      and every raw read live in the same block at once.
    /// @param payload The packed replaceKeys payload.
    function decodeReplaceKeys(
        bytes calldata payload
    )
        internal
        pure
        returns (
            KeyType kind,
            KeyType signingKind,
            uint256 n,
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[] calldata oldKeys,
            WOTSPlus.WinternitzAddress[] calldata newKeys
        )
    {
        // Header (2368 bytes): kind(32) + signingKind(32) + n(32) +
        // currentKey(64) + nextKey(64) + pqSig(2144). Read `n` first so the
        // expected-length check is exact rather than a >= minimum.
        if (payload.length < 2368) {
            revert MalformedPayload(2368, payload.length);
        }
        assembly {
            n := calldataload(add(payload.offset, 64))
        }
        // Solidity 0.8 checked arithmetic: an absurdly large `n` overflows
        // here and reverts before the length comparison runs, so we never
        // index into payload with a wrapped offset.
        uint256 expectedLen = 2368 + 2 * n * 64;
        if (payload.length != expectedLen) {
            revert MalformedPayload(expectedLen, payload.length);
        }

        uint256 raw;
        assembly {
            raw := calldataload(payload.offset)
        }
        kind = KeyType(raw);
        assembly {
            raw := calldataload(add(payload.offset, 32))
        }
        signingKind = KeyType(raw);

        assembly {
            currentKey := add(payload.offset, 96)
            nextKey := add(payload.offset, 160)
            pqSig := add(payload.offset, 224)
        }
        assembly {
            oldKeys.offset := add(payload.offset, 2368)
            oldKeys.length := n
            newKeys.offset := add(payload.offset, add(2368, mul(n, 64)))
            newKeys.length := n
        }
    }

    /// @dev Decodes the resetKeyset payload.
    ///      Layout: [0:32) kind, [32:64) signingKind,
    ///              [64:128) currentKey, [128:192) nextKey,
    ///              [192:2336) pqSig, [2336:2976) newKeys[10].
    ///      Both `kind` and `signingKind` are encoded as left-padded uint256s;
    ///      the enum cast implicitly validates the range via Solidity 0.8 panic.
    ///      No explicit `n` in the payload — the keyset size is fixed at 10
    ///      under the always-10 invariant, so the structural length check is
    ///      an exact 2976-byte equality.
    /// @param payload The packed resetKeyset payload (2976 bytes).
    function decodeResetKeyset(
        bytes calldata payload
    )
        internal
        pure
        returns (
            KeyType kind,
            KeyType signingKind,
            WOTSPlus.WinternitzAddress calldata currentKey,
            WOTSPlus.WinternitzAddress calldata nextKey,
            WOTSPlus.WinternitzElements calldata pqSig,
            WOTSPlus.WinternitzAddress[10] calldata newKeys
        )
    {
        if (payload.length != 2976) {
            revert MalformedPayload(2976, payload.length);
        }

        uint256 raw;
        assembly {
            raw := calldataload(payload.offset)
        }
        kind = KeyType(raw);
        assembly {
            raw := calldataload(add(payload.offset, 32))
        }
        signingKind = KeyType(raw);

        assembly {
            currentKey := add(payload.offset, 64)
            nextKey := add(payload.offset, 128)
            pqSig := add(payload.offset, 192)
            newKeys := add(payload.offset, 2336)
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
        if (signature.length != 2273) {
            revert MalformedPayload(2273, signature.length);
        }
        assembly {
            verifier := signature.offset
            pqSig := add(signature.offset, 64)
        }
        ecdsaSig = signature[2208:2273];
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        ENCODERS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Encodes the saveWallet payload.
    /// @return The packed payload (4192 bytes).
    function encodeSaveWallet(
        WOTSPlus.WinternitzAddress memory currentDisasterKey,
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[10] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys,
        WOTSPlus.WinternitzAddress[10] memory newVerificationKeys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(
            currentDisasterKey.publicSeed,
            currentDisasterKey.publicKeyHash,
            newDisasterKey.publicSeed,
            newDisasterKey.publicKeyHash,
            pqSig.elements
        );
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            payload = abi.encodePacked(
                payload,
                newTransactionKeys[i].publicSeed,
                newTransactionKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            payload = abi.encodePacked(
                payload,
                newRecoveryKeys[i].publicSeed,
                newRecoveryKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            payload = abi.encodePacked(
                payload,
                newVerificationKeys[i].publicSeed,
                newVerificationKeys[i].publicKeyHash
            );
        }
        return payload;
    }

    /// @dev Encodes the init payload.
    /// @return The packed payload (2048 bytes).
    function encodeInit(
        WOTSPlus.WinternitzAddress memory disasterRecoveryKey,
        WOTSPlus.WinternitzAddress memory ownershipKey,
        WOTSPlus.WinternitzAddress[10] memory transactionKeys,
        WOTSPlus.WinternitzAddress[10] memory recoveryKeys,
        WOTSPlus.WinternitzAddress[10] memory verificationKeys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(
            disasterRecoveryKey.publicSeed,
            disasterRecoveryKey.publicKeyHash,
            ownershipKey.publicSeed,
            ownershipKey.publicKeyHash
        );
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            payload = abi.encodePacked(
                payload,
                transactionKeys[i].publicSeed,
                transactionKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            payload = abi.encodePacked(
                payload,
                recoveryKeys[i].publicSeed,
                recoveryKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            payload = abi.encodePacked(
                payload,
                verificationKeys[i].publicSeed,
                verificationKeys[i].publicKeyHash
            );
        }
        return payload;
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
    /// @return The packed payload (4288 bytes).
    function encodeOwnershipTransfer(
        WOTSPlus.WinternitzAddress memory currentOwnershipKey,
        WOTSPlus.WinternitzAddress memory newOwnershipKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address newOwner,
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzAddress[10] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys,
        WOTSPlus.WinternitzAddress[10] memory newVerificationKeys
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
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            payload = abi.encodePacked(
                payload,
                newTransactionKeys[i].publicSeed,
                newTransactionKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            payload = abi.encodePacked(
                payload,
                newRecoveryKeys[i].publicSeed,
                newRecoveryKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < MAX_KEYS; i++) {
            payload = abi.encodePacked(
                payload,
                newVerificationKeys[i].publicSeed,
                newVerificationKeys[i].publicKeyHash
            );
        }
        return payload;
    }

    /// @dev Encodes the replaceKeys payload. `n` is encoded explicitly even
    ///      though `oldKeys.length` would suffice — the wire format carries
    ///      it as a structural length-check field so `decodeReplaceKeys` can
    ///      reject payloads whose stride and `n` disagree.
    /// @return The packed payload (2368 + 2*n*64 bytes).
    function encodeReplaceKeys(
        KeyType kind,
        KeyType signingKind,
        uint256 n,
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[] memory oldKeys,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(kind)),
            bytes32(uint256(signingKind)),
            bytes32(n),
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            pqSig.elements
        );
        for (uint256 i = 0; i < oldKeys.length; i++) {
            payload = abi.encodePacked(
                payload,
                oldKeys[i].publicSeed,
                oldKeys[i].publicKeyHash
            );
        }
        for (uint256 i = 0; i < newKeys.length; i++) {
            payload = abi.encodePacked(
                payload,
                newKeys[i].publicSeed,
                newKeys[i].publicKeyHash
            );
        }
        return payload;
    }

    /// @dev Encodes the resetKeyset payload (2976 bytes).
    /// @return The packed payload.
    function encodeResetKeyset(
        KeyType kind,
        KeyType signingKind,
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[10] memory newKeys
    ) internal pure returns (bytes memory) {
        bytes memory payload = abi.encodePacked(
            bytes32(uint256(kind)),
            bytes32(uint256(signingKind)),
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            pqSig.elements
        );
        for (uint256 i = 0; i < 10; i++) {
            payload = abi.encodePacked(
                payload,
                newKeys[i].publicSeed,
                newKeys[i].publicKeyHash
            );
        }
        return payload;
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
    /// @return The packed payload (4480 bytes).
    function encodeRecoveryUpgrade(
        WOTSPlus.WinternitzAddress memory currentRecoveryKey,
        WOTSPlus.WinternitzAddress memory newRecoveryKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress memory verifier,
        WOTSPlus.WinternitzElements memory verifySig
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                currentRecoveryKey.publicSeed,
                currentRecoveryKey.publicKeyHash,
                newRecoveryKey.publicSeed,
                newRecoveryKey.publicKeyHash,
                pqSig.elements,
                verifier.publicSeed,
                verifier.publicKeyHash,
                verifySig.elements
            );
    }

    /// @dev Encodes the full upgradeToAndCall payload (auth + verification + migration).
    /// @return The packed payload (6529 bytes).
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

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          HASHERS                              */
    /*  NOTE: WOTS+ signatures are incompatible with EIP-712. These  */
    /*  digests use domain tags instead of EIP-712 structured data.  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev keccak256(abi.encode(EXECUTE_TAG, chainId, wallet, s1, h1, s2, h2,
    ///                            target, value, opdataHash, fee))
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

    /// @dev keccak256(abi.encode(WITHDRAW_DEPOSIT_TAG, chainId, wallet,
    ///                            s1, h1, s2, h2, to, amount))
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

    /// @dev keccak256(abi.encode(UPGRADE_TAG, chainId, wallet, newImpl, s1, h1, s2, h2,
    ///                           shouldMigrate, migratorPayloadHash))
    ///      `migratorPayloadHash = keccak256(migratorPayload)` over the full 2048-byte
    ///      on-wire slot (zero-filled when shouldMigrate is false).
    function upgradeDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bool shouldMigrate,
        bytes32 migratorPayloadHash
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
                h2,
                bytes32(uint256(shouldMigrate ? 1 : 0)),
                migratorPayloadHash
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

    /// @dev keccak256(abi.encode(ERC4337_EXECUTE_TAG, chainId, wallet,
    ///                            s1, h1, s2, h2, userOpHash, fee))
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

    /// @dev keccak256(abi.encode(UPGRADE_RECOVERY_TAG, chainId, wallet, newImpl,
    ///                           currentSeed, currentHash, newSeed, newHash))
    ///      Used by recoveryUpgrade. Binds the current (consumed) recovery key and the
    ///      replacement recovery key so a signature cannot be separated from the key
    ///      pair it authorizes.
    function upgradeRecoveryDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 currentSeed,
        bytes32 currentHash,
        bytes32 newSeed,
        bytes32 newHash
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                UPGRADE_RECOVERY_TAG,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                bytes32(uint256(uint160(newImplementation))),
                currentSeed,
                currentHash,
                newSeed,
                newHash
            );
    }

    /// @dev keccak256(abi.encode(TRANSFER_OWNERSHIP_TAG, chainId, wallet, s1, h1, s2, h2,
    ///                           newOwner, keysHash))
    ///      where `keysHash = keccak256(abi.encode(newDisasterKey, newTransactionKeys,
    ///      newRecoveryKeys, newVerificationKeys))`. The ownership-transfer digest
    ///      commits to the entire re-initialization bundle so the WOTS+ signature
    ///      cannot be separated from the key material it installs.
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

    /// @dev Returns the digest that `replaceKeys` signs over. The tag is
    ///      selected per `(signingKind, kind)` so a signature cannot be lifted
    ///      across either axis (signing keyset OR target keyset). Six tag
    ///      cases:
    ///        Tx-sign,   Tx-target       → REPLACE_KEYS_TXSIGN_TX_TAG
    ///        Tx-sign,   Recovery-target → REPLACE_KEYS_TXSIGN_RECOVERY_TAG
    ///        Tx-sign,   Verify-target   → REPLACE_KEYS_TXSIGN_VERIFY_TAG
    ///        Rec-sign,  Tx-target       → REPLACE_KEYS_RECSIGN_TX_TAG
    ///        Rec-sign,  Recovery-target → REPLACE_KEYS_RECSIGN_RECOVERY_TAG
    ///        Rec-sign,  Verify-target   → REPLACE_KEYS_RECSIGN_VERIFY_TAG
    ///      `signingKind == Verification` is rejected by the wallet before
    ///      this is invoked; the dispatch below falls into the Recovery-sign
    ///      branch if reached, but the wallet's `_verifyAndRotate` would also
    ///      reject the membership check.
    ///      keccak256(abi.encode(tag, chainId, wallet, n,
    ///                           s1, h1, s2, h2, oldKeysHash, newKeysHash))
    function replaceKeysDigest(
        KeyType kind,
        KeyType signingKind,
        uint256 n,
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 oldKeysHash,
        bytes32 newKeysHash
    ) internal pure returns (bytes32) {
        bytes32 tag;
        if (signingKind == KeyType.Transaction) {
            if (kind == KeyType.Transaction) {
                tag = REPLACE_KEYS_TXSIGN_TX_TAG;
            } else if (kind == KeyType.Recovery) {
                tag = REPLACE_KEYS_TXSIGN_RECOVERY_TAG;
            } else {
                tag = REPLACE_KEYS_TXSIGN_VERIFY_TAG;
            }
        } else {
            if (kind == KeyType.Transaction) {
                tag = REPLACE_KEYS_RECSIGN_TX_TAG;
            } else if (kind == KeyType.Recovery) {
                tag = REPLACE_KEYS_RECSIGN_RECOVERY_TAG;
            } else {
                tag = REPLACE_KEYS_RECSIGN_VERIFY_TAG;
            }
        }
        return
            EfficientHashLib.hash(
                tag,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                bytes32(n),
                s1,
                h1,
                s2,
                h2,
                oldKeysHash,
                newKeysHash
            );
    }

    /// @dev Returns the digest that `resetKeyset` signs over. The tag is
    ///      selected per `(signingKind, kind)` so a signature cannot be lifted
    ///      across either axis (signing keyset OR target keyset). Six tag
    ///      cases:
    ///        Tx-sign,   Tx-target       → RESET_KEYSET_TXSIGN_TX_TAG
    ///        Tx-sign,   Recovery-target → RESET_KEYSET_TXSIGN_RECOVERY_TAG
    ///        Tx-sign,   Verify-target   → RESET_KEYSET_TXSIGN_VERIFY_TAG
    ///        Rec-sign,  Tx-target       → RESET_KEYSET_RECSIGN_TX_TAG
    ///        Rec-sign,  Recovery-target → RESET_KEYSET_RECSIGN_RECOVERY_TAG
    ///        Rec-sign,  Verify-target   → RESET_KEYSET_RECSIGN_VERIFY_TAG
    ///      `signingKind == Verification` is rejected by the wallet before
    ///      this is invoked; the dispatch below falls into the Recovery-sign
    ///      branch if reached, but the wallet's `_verifyAndRotate` would also
    ///      reject the membership check.
    ///      keccak256(abi.encode(tag, chainId, wallet,
    ///                           s1, h1, s2, h2, newKeysHash))
    function resetKeysetDigest(
        KeyType kind,
        KeyType signingKind,
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 newKeysHash
    ) internal pure returns (bytes32) {
        bytes32 tag;
        if (signingKind == KeyType.Transaction) {
            if (kind == KeyType.Transaction) {
                tag = RESET_KEYSET_TXSIGN_TX_TAG;
            } else if (kind == KeyType.Recovery) {
                tag = RESET_KEYSET_TXSIGN_RECOVERY_TAG;
            } else {
                tag = RESET_KEYSET_TXSIGN_VERIFY_TAG;
            }
        } else {
            if (kind == KeyType.Transaction) {
                tag = RESET_KEYSET_RECSIGN_TX_TAG;
            } else if (kind == KeyType.Recovery) {
                tag = RESET_KEYSET_RECSIGN_RECOVERY_TAG;
            } else {
                tag = RESET_KEYSET_RECSIGN_VERIFY_TAG;
            }
        }
        return
            EfficientHashLib.hash(
                tag,
                bytes32(chainId),
                bytes32(uint256(uint160(wallet))),
                s1,
                h1,
                s2,
                h2,
                newKeysHash
            );
    }

    /// @dev keccak256(abi.encode(ERC1271_TAG, chainId, wallet,
    ///                            verifierSeed, verifierHash, messageHash))
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
    ///      where `keysHash = keccak256(abi.encode(newTransactionKeys,
    ///      newRecoveryKeys, newVerificationKeys))`.
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
