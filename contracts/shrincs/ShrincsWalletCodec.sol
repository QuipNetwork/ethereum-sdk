// Copyright (C) 2026 quip.network
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

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";

/// @title ShrincsWalletCodec
/// @notice Decoders and canonical-context builders for `ShrincsWallet`.
/// @dev Owner-path wallet functions take SHRINCS structs as direct `calldata` parameters
///      (Solidity supplies bounds-checked calldata refs), so they do NOT route through this
///      codec for decoding. This codec only decodes the operations whose ABI is fixed by an
///      external standard and therefore arrives as a `bytes` blob: `initialize` (factory ABI),
///      ERC-4337 `userOp.signature`, UUPS `upgradeToAndCall` `data`, and ERC-1271 `signature`.
///      SHRINCS verify functions require `calldata` struct args and Solidity cannot
///      `abi.decode` into `calldata`, so each blob decoder hands back calldata struct pointers
///      using the standard ABI head/tail offset layout (`ptr = blob.offset + offset_word`).
library ShrincsWalletCodec {
    /// @notice Thrown when a `bytes` blob is too short to contain its fixed ABI head.
    error MalformedPayload(uint256 expectedMin, uint256 actual);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      DOMAIN / TAGS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Wallet signing-domain tag; combined with chainId + wallet address into the
    ///      `ActionContext.domainSeparator` so signatures cannot replay across chains/wallets.
    bytes32 internal constant DOMAIN_TAG = keccak256("quip-shrincs-wallet-v1");

    /// @dev `ActionContext.actionType` discriminators — one per operation family. The SHRINCS
    ///      library binds `actionType` into `statefulActionMessageHash` /
    ///      `statelessActionMessageHash`, so a distinct constant per operation is the
    ///      per-operation domain tag.
    bytes32 internal constant ACTION_ERC4337_EXECUTE =
        keccak256("quip.shrincs.action.erc4337Execute");
    bytes32 internal constant ACTION_EXECUTE =
        keccak256("quip.shrincs.action.execute");
    bytes32 internal constant ACTION_WITHDRAW =
        keccak256("quip.shrincs.action.withdrawDeposit");
    bytes32 internal constant ACTION_UPGRADE =
        keccak256("quip.shrincs.action.upgrade");
    bytes32 internal constant ACTION_TRANSFER_OWNERSHIP =
        keccak256("quip.shrincs.action.transferOwnership");
    bytes32 internal constant ACTION_SET_ERC1271_KEY =
        keccak256("quip.shrincs.action.setErc1271Key");
    bytes32 internal constant ACTION_ROTATE_KEY =
        keccak256("quip.shrincs.action.rotateKey");
    bytes32 internal constant ACTION_ERC1271 =
        keccak256("quip.shrincs.action.erc1271");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       DECODERS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Decodes the factory-supplied init payload, the ABI encoding of
    ///      `(bytes32 commitment, bytes32 pkSeed, PublicKey mainBundle, uint8 parameterSetId,
    ///       bytes32 erc1271Commitment, uint8 erc1271ParameterSetId)`.
    ///      `commitment` and `pkSeed` occupy `payload[0:32]` / `[32:64]` so the factory's
    ///      opaque `QuipCreated` indexing read lands on meaningful handles.
    function decodeInit(
        bytes calldata payload
    )
        internal
        pure
        returns (
            bytes32 commitment,
            bytes32 pkSeed,
            ShrincsTypes.PublicKey calldata mainBundle,
            uint8 parameterSetId,
            bytes32 erc1271Commitment,
            uint8 erc1271ParameterSetId
        )
    {
        // Head is six 32-byte words (one is the PublicKey tail offset).
        if (payload.length < 0xc0)
            revert MalformedPayload(0xc0, payload.length);
        assembly {
            let o := payload.offset
            commitment := calldataload(o)
            pkSeed := calldataload(add(o, 0x20))
            mainBundle := add(o, calldataload(add(o, 0x40)))
            parameterSetId := and(calldataload(add(o, 0x60)), 0xff)
            erc1271Commitment := calldataload(add(o, 0x80))
            erc1271ParameterSetId := and(calldataload(add(o, 0xa0)), 0xff)
        }
    }

    /// @dev Decodes the ERC-4337 `userOp.signature` field, which by convention carries *both*
    ///      SHRINCS structs: it is the ABI encoding of `(PublicKey publicKey,
    ///      StatefulSignature signature)`. Note the name collision — the outer `signature` is
    ///      ERC-4337's `userOp` field; the inner `signature` is the SHRINCS stateful signature
    ///      that travels inside it alongside the public key.
    function decodeUserOpSignature(
        bytes calldata sig
    )
        internal
        pure
        returns (
            ShrincsTypes.PublicKey calldata publicKey,
            ShrincsTypes.StatefulSignature calldata signature
        )
    {
        if (sig.length < 0x40) revert MalformedPayload(0x40, sig.length);
        assembly {
            let o := sig.offset
            publicKey := add(o, calldataload(o))
            signature := add(o, calldataload(add(o, 0x20)))
        }
    }

    /// @dev Decodes the UUPS `upgradeToAndCall` `data` blob, the ABI encoding of
    ///      `(PublicKey publicKey, StatefulSignature signature, bool shouldMigrate,
    ///       bytes migratorPayload)`.
    function decodeUpgradeAuth(
        bytes calldata data
    )
        internal
        pure
        returns (
            ShrincsTypes.PublicKey calldata publicKey,
            ShrincsTypes.StatefulSignature calldata signature,
            bool shouldMigrate,
            bytes calldata migratorPayload
        )
    {
        if (data.length < 0x80) {
            revert MalformedPayload(0x80, data.length);
        }
        assembly {
            let o := data.offset
            publicKey := add(o, calldataload(o))
            signature := add(o, calldataload(add(o, 0x20)))
            shouldMigrate := iszero(iszero(calldataload(add(o, 0x40))))
            let mo := add(o, calldataload(add(o, 0x60)))
            migratorPayload.offset := add(mo, 0x20)
            migratorPayload.length := calldataload(mo)
        }
    }

    /// @dev Decodes the ERC-1271 `signature` blob, the ABI encoding of
    ///      `(PublicKey publicKey, StatelessSignature signature, bytes ecdsaSig)`.
    function decodeErc1271Signature(
        bytes calldata sig
    )
        internal
        pure
        returns (
            ShrincsTypes.PublicKey calldata publicKey,
            ShrincsTypes.StatelessSignature calldata signature,
            bytes calldata ecdsaSig
        )
    {
        if (sig.length < 0x60) {
            revert MalformedPayload(0x60, sig.length);
        }
        assembly {
            let o := sig.offset
            publicKey := add(o, calldataload(o))
            signature := add(o, calldataload(add(o, 0x20)))
            let eo := add(o, calldataload(add(o, 0x40)))
            ecdsaSig.offset := add(eo, 0x20)
            ecdsaSig.length := calldataload(eo)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   CONTEXT BUILDERS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Assembles a canonical `ActionContext`. The wallet supplies `domainSeparator`
    ///      (bound to chainId + wallet address) and its freshness state.
    function buildActionContext(
        bytes32 domainSeparator,
        uint256 nonce,
        uint256 keyVersion,
        bytes32 actionType,
        bytes32 payloadHash
    ) internal pure returns (ShrincsTypes.ActionContext memory) {
        return
            ShrincsTypes.ActionContext({
                domainSeparator: domainSeparator,
                nonce: nonce,
                keyVersion: keyVersion,
                actionType: actionType,
                payloadHash: payloadHash
            });
    }

    /// @dev Assembles a canonical `RotationContext` for the break-glass stateless rotation.
    function buildRotationContext(
        bytes32 domainSeparator,
        uint256 nonce,
        uint256 keyVersion
    ) internal pure returns (ShrincsTypes.RotationContext memory) {
        return
            ShrincsTypes.RotationContext({
                domainSeparator: domainSeparator,
                nonce: nonce,
                keyVersion: keyVersion
            });
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PAYLOAD HASHES                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `ActionContext.payloadHash` for the ERC-4337 execute path: binds the EntryPoint
    ///      userOpHash (which already commits to target/value/data/nonce) and the execute fee.
    function erc4337PayloadHash(
        bytes32 userOpHash,
        uint256 fee
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(userOpHash, bytes32(fee));
    }

    /// @dev `payloadHash` for the owner `execute` path.
    function executePayloadHash(
        address target,
        uint256 value,
        bytes32 dataHash,
        uint256 fee
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                bytes32(uint256(uint160(target))),
                bytes32(value),
                dataHash,
                bytes32(fee)
            );
    }

    /// @dev `payloadHash` for the `withdrawDepositTo` path.
    function withdrawPayloadHash(
        address to,
        uint256 amount
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                bytes32(uint256(uint160(to))),
                bytes32(amount)
            );
    }

    /// @dev `payloadHash` for the `upgradeToAndCall` path.
    function upgradePayloadHash(
        address newImplementation,
        bool shouldMigrate,
        bytes32 migratorHash
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                bytes32(uint256(uint160(newImplementation))),
                bytes32(uint256(shouldMigrate ? 1 : 0)),
                migratorHash
            );
    }

    /// @dev `payloadHash` for the `transferOwnership` (atomic handover) path. Cross-binds the new
    ///      classical owner to the incoming key bundle so the stateful owner-binding signature and
    ///      the stateless rotation signature cannot be mixed across separate handover attempts.
    function transferOwnershipPayloadHash(
        address newOwner,
        bytes32 nextCommitment
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                bytes32(uint256(uint160(newOwner))),
                nextCommitment
            );
    }

    /// @dev `payloadHash` for the `setErc1271Key` path.
    function setErc1271KeyPayloadHash(
        bytes32 newCommitment,
        uint8 newParameterSetId
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                newCommitment,
                bytes32(uint256(newParameterSetId))
            );
    }

    /// @dev `payloadHash` for the stateful `rotateKey` path: binds the next stateful subkey's
    ///      bundle commitment and parameter set.
    function rotateKeyPayloadHash(
        bytes32 nextCommitment,
        uint8 nextParameterSetId
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                nextCommitment,
                bytes32(uint256(nextParameterSetId))
            );
    }
}
