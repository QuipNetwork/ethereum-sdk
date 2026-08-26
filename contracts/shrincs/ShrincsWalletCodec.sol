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

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
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

    /// @dev Deploy signing-domain tag (e3r). Combined with chainId + the FACTORY
    ///      address into the deploy `ActionContext.domainSeparator`. The deploy
    ///      authorization binds the factory (the authority that supplies the chainId
    ///      and quipDeployChainIndex) because the wallet address does not yet exist.
    bytes32 internal constant DEPLOY_DOMAIN_TAG =
        keccak256("quip-shrincs-deploy-v1");

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
    bytes32 internal constant ACTION_MARK_LEAVES_USED =
        keccak256("quip.shrincs.action.markLeavesUsed");
    bytes32 internal constant ACTION_ERC1271 =
        keccak256("quip.shrincs.action.erc1271");
    /// @dev Deploy authorization action type (e3r). Proves the main-key holder
    ///      authorizes deploying this key at (vaultId, owner) on the factory's chain.
    bytes32 internal constant ACTION_DEPLOY =
        keccak256("quip.shrincs.action.deploy");

    /// @dev Per-path tags folded into `RotationContext.domainSeparator` (see
    ///      `rotationDomainSeparator`). `RotationContext` carries no action discriminator, so
    ///      without these a recovery signature produced for a `transferOwnership` bundle would
    ///      double as a complete `recoverWallet` input — the submitter could drop the stateful
    ///      owner-binding signature and downgrade a signed handover into a plain rotation.
    ///      Distinct tags make the two stateless-rotation paths mutually invalid.
    bytes32 internal constant ROTATION_DOMAIN_RECOVER_WALLET =
        keccak256("quip.shrincs.rotation.recoverWallet");
    bytes32 internal constant ROTATION_DOMAIN_TRANSFER_OWNERSHIP =
        keccak256("quip.shrincs.rotation.transferOwnership");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    IDENTITY (QSalt1)                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The 6-byte `QSalt1` marker (ASCII "QSalt1") that prefixes a QSalt1
    ///      vault id. A CREATE3 salt carrying this prefix is a commitment-identity
    ///      salt whose low 26 bytes are `qsalt1Tail`.
    bytes6 internal constant QSALT1_PREFIX = 0x5153616c7431;

    /// @dev The low 26 bytes of `keccak256(abi.encode(statefulC, statelessC, owner))`.
    ///      Left-shifting by 48 bits drops the high 6 bytes, so `bytes26` keeps
    ///      keccak bytes [6..32) — the segment that follows the prefix in a
    ///      `qsalt1VaultId`.
    function qsalt1Tail(
        bytes32 statefulC,
        bytes32 statelessC,
        address owner
    ) internal pure returns (bytes26) {
        return
            bytes26(
                keccak256(abi.encode(statefulC, statelessC, owner)) << 48
            );
    }

    /// @dev The identity-binding vault id (`QSalt1`): 32 bytes =
    ///      `QSALT1_PREFIX(6) ‖ qsalt1Tail(26)`. Binds the vault id to the
    ///      stateful/stateless commitments and the intended owner, so the
    ///      counterfactual address is a function of the wallet's identity. Mirrors
    ///      the SDK `qsalt1VaultId` byte-for-byte.
    function qsalt1VaultId(
        bytes32 statefulC,
        bytes32 statelessC,
        address owner
    ) internal pure returns (bytes32) {
        return
            bytes32(
                abi.encodePacked(
                    QSALT1_PREFIX,
                    qsalt1Tail(statefulC, statelessC, owner)
                )
            );
    }

    /// @dev True when `salt` carries the `QSalt1` marker in its high 6 bytes.
    function isQSalt1Salt(bytes32 salt) internal pure returns (bool) {
        return bytes6(salt) == QSALT1_PREFIX;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       DECODERS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Decodes the factory-supplied init payload, the ABI encoding of
    ///      `(bytes32 commitment, bytes32 pkSeed, PublicKey mainBundle, uint32 hashSuite,
    ///       bytes32 erc1271Commitment, uint32 erc1271HashSuite)`.
    ///      The payload is opaque to the factory; `commitment`/`pkSeed` landing at
    ///      `payload[0:32]` / `[32:64]` is just natural ABI head-word order, not a
    ///      layout constraint. The `initialize` payload appends a trailing
    ///      `bytes deployAuth` (7th head word) read separately by `decodeInitDeployAuth`;
    ///      this decoder ignores it (and `migrate` payloads omit it entirely).
    function decodeInit(
        bytes calldata payload
    )
        internal
        pure
        returns (
            bytes32 commitment,
            bytes32 pkSeed,
            SHRINCS.PublicKey calldata mainBundle,
            uint32 hashSuite,
            bytes32 erc1271Commitment,
            uint32 erc1271HashSuite
        )
    {
        // Head is six 32-byte words (one is the PublicKey tail offset).
        if (payload.length < 0xc0)
            revert MalformedPayload(0xc0, payload.length);
        bytes4 malformed = MalformedPayload.selector;
        assembly {
            let o := payload.offset
            let len := payload.length
            // Reverts MalformedPayload(off + 0x20, len) unless the head word a tail offset
            // points at is inside the slice. `len >= 0xc0` here, so `sub(len, 0x20)` never
            // underflows and `add(off, 0x20)` (an out-of-range diagnostic) may wrap harmlessly.
            function reqTail(off, l, m) {
                if gt(off, sub(l, 0x20)) {
                    mstore(0x00, m)
                    mstore(0x04, add(off, 0x20))
                    mstore(0x24, l)
                    revert(0x00, 0x44)
                }
            }
            commitment := calldataload(o)
            pkSeed := calldataload(add(o, 0x20))
            let mbOff := calldataload(add(o, 0x40))
            reqTail(mbOff, len, malformed)
            // Nested PublicKey tail bounds are out of scope here; those fields are read through
            // Solidity calldata accessors downstream, which bounds-check against calldatasize.
            mainBundle := add(o, mbOff)
            hashSuite := and(calldataload(add(o, 0x60)), 0xffffffff)
            erc1271Commitment := calldataload(add(o, 0x80))
            erc1271HashSuite := and(calldataload(add(o, 0xa0)), 0xffffffff)
        }
    }

    /// @dev Decodes the deploy authorization embedded in the `initialize` payload (e3r) — the
    ///      7th ABI head word of the init tuple (see `decodeInit`; the init payload gains a
    ///      trailing `bytes deployAuth`). `deployAuth` is itself the verify envelope
    ///      `abi.encode(SHRINCS.PublicKey pk, sig)` where `sig` is a `SHRINCS.Signature`
    ///      (stateful mode) or a `SPHINCSPlusC.Signature` (stateless mode); the wallet passes
    ///      it straight to the pinned verifier. Returns a calldata slice into `payload`.
    function decodeInitDeployAuth(
        bytes calldata payload
    ) internal pure returns (bytes calldata deployAuth) {
        // Head is seven 32-byte words; the 7th (index 6, offset 0xc0) is the `bytes` tail offset.
        if (payload.length < 0xe0)
            revert MalformedPayload(0xe0, payload.length);
        bytes4 malformed = MalformedPayload.selector;
        assembly {
            let o := payload.offset
            let len := payload.length
            let da := calldataload(add(o, 0xc0))
            // The length word must sit inside the slice: da + 0x20 <= len. `len >= 0xe0` here so
            // `sub(len, 0x20)` never underflows.
            if gt(da, sub(len, 0x20)) {
                mstore(0x00, malformed)
                mstore(0x04, add(da, 0x20))
                mstore(0x24, len)
                revert(0x00, 0x44)
            }
            let daLen := calldataload(add(o, da))
            // The deployAuth bytes must fit: da + 0x20 + daLen <= len. `da <= len - 0x20` was just
            // proven, so `sub(sub(len, 0x20), da)` cannot underflow.
            if gt(daLen, sub(sub(len, 0x20), da)) {
                mstore(0x00, malformed)
                mstore(0x04, add(add(da, 0x20), daLen))
                mstore(0x24, len)
                revert(0x00, 0x44)
            }
            deployAuth.offset := add(o, add(da, 0x20))
            deployAuth.length := daLen
        }
    }

    /// @dev Decodes the ERC-4337 `userOp.signature` field, which by convention carries the
    ///      SHRINCS structs plus the owner's ECDSA co-signature: it is the ABI encoding of
    ///      `(PublicKey publicKey, SHRINCS.Signature signature, bytes ecdsaSig)`. Note the name
    ///      collision — the outer `signature` is ERC-4337's `userOp` field; the inner
    ///      `signature` is the SHRINCS stateful signature that travels inside it.
    function decodeUserOpSignature(
        bytes calldata sig
    )
        internal
        pure
        returns (
            SHRINCS.PublicKey calldata publicKey,
            SHRINCS.Signature calldata signature,
            bytes calldata ecdsaSig
        )
    {
        // Head is three offset words (three dynamic tail types).
        if (sig.length < 0x60) revert MalformedPayload(0x60, sig.length);
        bytes4 malformed = MalformedPayload.selector;
        assembly {
            let o := sig.offset
            let len := sig.length
            // Reverts MalformedPayload(off + 0x20, len) unless the head word a tail offset
            // points at is inside the slice. `len >= 0x60` here, so `sub(len, 0x20)` never
            // underflows and `add(off, 0x20)` (an out-of-range diagnostic) may wrap harmlessly.
            function reqTail(off, l, m) {
                if gt(off, sub(l, 0x20)) {
                    mstore(0x00, m)
                    mstore(0x04, add(off, 0x20))
                    mstore(0x24, l)
                    revert(0x00, 0x44)
                }
            }
            let pkOff := calldataload(o)
            reqTail(pkOff, len, malformed)
            publicKey := add(o, pkOff)
            let sigOff := calldataload(add(o, 0x20))
            reqTail(sigOff, len, malformed)
            // Nested PublicKey/Signature tail bounds are out of scope here; those fields are read
            // through Solidity calldata accessors downstream, which bounds-check calldatasize.
            signature := add(o, sigOff)
            let eo := calldataload(add(o, 0x40))
            reqTail(eo, len, malformed)
            let ecLen := calldataload(add(o, eo))
            // The ecdsaSig bytes must fit: eo + 0x20 + ecLen <= len. `eo <= len - 0x20` was just
            // proven, so `sub(sub(len, 0x20), eo)` cannot underflow — no wrapped-sum trust.
            if gt(ecLen, sub(sub(len, 0x20), eo)) {
                mstore(0x00, malformed)
                mstore(0x04, add(add(eo, 0x20), ecLen))
                mstore(0x24, len)
                revert(0x00, 0x44)
            }
            ecdsaSig.offset := add(o, add(eo, 0x20))
            ecdsaSig.length := ecLen
        }
    }

    /// @dev Decodes the paymaster's sponsorship blob (the tail of `paymasterAndData`), the ABI
    ///      encoding of `(PublicKey publicKey, SHRINCS.Signature signature)`. The sponsorship
    ///      key is the paymaster's global stateful key — there is no ECDSA co-signer on this
    ///      blob (paymaster admin authority is owner-fiat), so it keeps the plain pair layout
    ///      the wallet's `decodeUserOpSignature` had before the co-signature was added.
    function decodeSponsorshipSignature(
        bytes calldata sig
    )
        internal
        pure
        returns (
            SHRINCS.PublicKey calldata publicKey,
            SHRINCS.Signature calldata signature
        )
    {
        // Head is two offset words (two dynamic tail types).
        if (sig.length < 0x40) revert MalformedPayload(0x40, sig.length);
        bytes4 malformed = MalformedPayload.selector;
        assembly {
            let o := sig.offset
            let len := sig.length
            // Reverts MalformedPayload(off + 0x20, len) unless the head word a tail offset
            // points at is inside the slice. `len >= 0x40` here, so `sub(len, 0x20)` never
            // underflows and `add(off, 0x20)` (an out-of-range diagnostic) may wrap harmlessly.
            function reqTail(off, l, m) {
                if gt(off, sub(l, 0x20)) {
                    mstore(0x00, m)
                    mstore(0x04, add(off, 0x20))
                    mstore(0x24, l)
                    revert(0x00, 0x44)
                }
            }
            let pkOff := calldataload(o)
            reqTail(pkOff, len, malformed)
            publicKey := add(o, pkOff)
            let sigOff := calldataload(add(o, 0x20))
            reqTail(sigOff, len, malformed)
            // Nested PublicKey/Signature tail bounds are out of scope here; those fields are read
            // through Solidity calldata accessors downstream, which bounds-check calldatasize.
            signature := add(o, sigOff)
        }
    }

    /// @dev Decodes the UUPS `upgradeToAndCall` `data` blob, the ABI encoding of
    ///      `(PublicKey publicKey, SHRINCS.Signature signature, bool shouldMigrate,
    ///       bytes migratorPayload, uint256 nonce)`. The action nonce the signer bound rides in
    ///      the blob (rather than being read live) so `verifyUpgrade` can rebuild the exact
    ///      signed context at any moment — both in the SDK's pre-flight staticcall (live nonce
    ///      == blob nonce) and in the post-consumption reachability probe (live == blob + 1).
    function decodeUpgradeAuth(
        bytes calldata data
    )
        internal
        pure
        returns (
            SHRINCS.PublicKey calldata publicKey,
            SHRINCS.Signature calldata signature,
            bool shouldMigrate,
            bytes calldata migratorPayload,
            uint256 nonce
        )
    {
        if (data.length < 0xa0) {
            revert MalformedPayload(0xa0, data.length);
        }
        bytes4 malformed = MalformedPayload.selector;
        assembly {
            let o := data.offset
            let len := data.length
            // Reverts MalformedPayload(off + 0x20, len) unless the head word a tail offset
            // points at is inside the slice. `len >= 0xa0` here, so `sub(len, 0x20)` never
            // underflows and `add(off, 0x20)` (an out-of-range diagnostic) may wrap harmlessly.
            function reqTail(off, l, m) {
                if gt(off, sub(l, 0x20)) {
                    mstore(0x00, m)
                    mstore(0x04, add(off, 0x20))
                    mstore(0x24, l)
                    revert(0x00, 0x44)
                }
            }
            let pkOff := calldataload(o)
            reqTail(pkOff, len, malformed)
            publicKey := add(o, pkOff)
            let sigOff := calldataload(add(o, 0x20))
            reqTail(sigOff, len, malformed)
            // Nested PublicKey/Signature tail bounds are out of scope here; those fields are read
            // through Solidity calldata accessors downstream, which bounds-check calldatasize.
            signature := add(o, sigOff)
            shouldMigrate := iszero(iszero(calldataload(add(o, 0x40))))
            let mo := calldataload(add(o, 0x60))
            reqTail(mo, len, malformed)
            let mLen := calldataload(add(o, mo))
            // The migratorPayload bytes must fit: mo + 0x20 + mLen <= len. `mo <= len - 0x20` was
            // just proven, so `sub(sub(len, 0x20), mo)` cannot underflow — no wrapped-sum trust.
            if gt(mLen, sub(sub(len, 0x20), mo)) {
                mstore(0x00, malformed)
                mstore(0x04, add(add(mo, 0x20), mLen))
                mstore(0x24, len)
                revert(0x00, 0x44)
            }
            migratorPayload.offset := add(o, add(mo, 0x20))
            migratorPayload.length := mLen
            nonce := calldataload(add(o, 0x80))
        }
    }

    /// @dev Decodes the ERC-1271 `signature` blob, the ABI encoding of
    ///      `(PublicKey publicKey, SPHINCSPlusC.Signature signature, bytes ecdsaSig)`.
    function decodeErc1271Signature(
        bytes calldata sig
    )
        internal
        pure
        returns (
            SHRINCS.PublicKey calldata publicKey,
            SPHINCSPlusC.Signature calldata signature,
            bytes calldata ecdsaSig
        )
    {
        if (sig.length < 0x60) {
            revert MalformedPayload(0x60, sig.length);
        }
        bytes4 malformed = MalformedPayload.selector;
        assembly {
            let o := sig.offset
            let len := sig.length
            // Reverts MalformedPayload(off + 0x20, len) unless the head word a tail offset
            // points at is inside the slice. `len >= 0x60` here, so `sub(len, 0x20)` never
            // underflows and `add(off, 0x20)` (an out-of-range diagnostic) may wrap harmlessly.
            function reqTail(off, l, m) {
                if gt(off, sub(l, 0x20)) {
                    mstore(0x00, m)
                    mstore(0x04, add(off, 0x20))
                    mstore(0x24, l)
                    revert(0x00, 0x44)
                }
            }
            let pkOff := calldataload(o)
            reqTail(pkOff, len, malformed)
            publicKey := add(o, pkOff)
            let sigOff := calldataload(add(o, 0x20))
            reqTail(sigOff, len, malformed)
            // Nested PublicKey/Signature tail bounds are out of scope here; those fields are read
            // through Solidity calldata accessors downstream, which bounds-check calldatasize.
            signature := add(o, sigOff)
            let eo := calldataload(add(o, 0x40))
            reqTail(eo, len, malformed)
            let ecLen := calldataload(add(o, eo))
            // The ecdsaSig bytes must fit: eo + 0x20 + ecLen <= len. `eo <= len - 0x20` was just
            // proven, so `sub(sub(len, 0x20), eo)` cannot underflow — no wrapped-sum trust.
            if gt(ecLen, sub(sub(len, 0x20), eo)) {
                mstore(0x00, malformed)
                mstore(0x04, add(add(eo, 0x20), ecLen))
                mstore(0x24, len)
                revert(0x00, 0x44)
            }
            ecdsaSig.offset := add(o, add(eo, 0x20))
            ecdsaSig.length := ecLen
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
    ) internal pure returns (SHRINCS.ActionContext memory) {
        return
            SHRINCS.ActionContext({
                domainSeparator: domainSeparator,
                nonce: nonce,
                keyVersion: keyVersion,
                actionType: actionType,
                payloadHash: payloadHash
            });
    }

    /// @dev Derives the `RotationContext.domainSeparator` for one stateless-rotation path by
    ///      folding a per-path `ROTATION_DOMAIN_*` tag into the wallet's base signing domain.
    ///      The result is opaque to the SHRINCS library — the tag rides inside the separator.
    function rotationDomainSeparator(
        bytes32 base,
        bytes32 tag
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(base, tag);
    }

    /// @dev Assembles a canonical `RotationContext` for a stateless rotation; `domainSeparator`
    ///      must already be path-tagged via `rotationDomainSeparator`.
    function buildRotationContext(
        bytes32 domainSeparator,
        uint256 nonce,
        uint256 keyVersion
    ) internal pure returns (SHRINCS.RotationContext memory) {
        return
            SHRINCS.RotationContext({
                domainSeparator: domainSeparator,
                nonce: nonce,
                keyVersion: keyVersion
            });
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    PAYLOAD HASHES                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `ActionContext.payloadHash` for the ERC-4337 execute path: binds the EntryPoint
    ///      userOpHash, which already commits to target/value/data/nonce — and, via `callData`,
    ///      to the `maxFee` execution parameter. No fee word here: validation must not read the
    ///      factory's live fee (ERC-7562 STO-033).
    function erc4337PayloadHash(
        bytes32 userOpHash
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(userOpHash);
    }

    /// @dev `payloadHash` for the owner `execute` path. `maxFee` is the signer's fee ceiling,
    ///      not the charged amount: execution reads the factory's live fee and reverts only if
    ///      it exceeds this cap.
    function executePayloadHash(
        address target,
        uint256 value,
        bytes32 dataHash,
        uint256 maxFee
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                bytes32(uint256(uint160(target))),
                bytes32(value),
                dataHash,
                bytes32(maxFee)
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
        uint32 newHashSuite
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                newCommitment,
                bytes32(uint256(newHashSuite))
            );
    }

    /// @dev `payloadHash` for the stateful `rotateKey` path: binds the next stateful subkey's
    ///      bundle commitment.
    function rotateKeyPayloadHash(
        bytes32 nextCommitment
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(nextCommitment);
    }

    /// @dev `payloadHash` for the `markLeavesUsed` (batch leaf revocation) path. `leavesHash`
    ///      commits to the exact target array — one 32-byte word per leaf index, in order —
    ///      so a submitter can neither add nor drop targets from a signed revocation.
    function markLeavesUsedPayloadHash(
        bytes32 leavesHash
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(leavesHash);
    }

    /// @dev `payloadHash` for the deploy authorization (e3r). Binds the vault, the
    ///      intended owner, the ERC-1271 commitment, and the quipDeployChainIndex so a
    ///      deploy signature authorizes exactly one (vaultId, owner, erc1271, chainIndex)
    ///      tuple. The main-key commitment is authenticated by the signature itself; the
    ///      chain and factory are bound through the deploy `domainSeparator`. Mirrors the
    ///      SDK `deployPayloadHash` word-for-word.
    function deployPayloadHash(
        bytes32 vaultId,
        address owner,
        bytes32 erc1271Commitment,
        uint256 quipDeployChainIndex
    ) internal pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                vaultId,
                bytes32(uint256(uint160(owner))),
                erc1271Commitment,
                bytes32(quipDeployChainIndex)
            );
    }
}
