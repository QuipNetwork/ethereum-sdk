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

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {StatelessLayout} from "@quip.network/hashsigs-solidity-0.4.0/contracts/StatelessLayout.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";

/// @title ShrincsWalletCodec
/// @notice Decoders, stateless-payload builder and canonical-context builders for
///         `ShrincsWallet`.
/// @dev Owner-path wallet functions take SHRINCS structs as direct `calldata` parameters
///      (Solidity supplies bounds-checked calldata refs), so they do NOT route through this
///      codec for decoding. This codec only decodes the operations whose ABI is fixed by an
///      external standard and therefore arrives as a `bytes` blob: `initialize` (factory ABI),
///      ERC-4337 `userOp.signature`, UUPS `upgradeToAndCall` `data`, and ERC-1271 `signature`.
///      SHRINCS verify functions require `calldata` struct args and Solidity cannot
///      `abi.decode` into `calldata`, so each ABI blob decoder hands back calldata struct
///      pointers using the standard ABI head/tail offset layout
///      (`ptr = blob.offset + offset_word`). The ERC-1271 `signature` is the exception: it is a
///      fixed-layout envelope with no offsets ("ERC-1271 ENVELOPE LAYOUT" below).
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
    bytes32 internal constant ACTION_MARK_LEAVES_USED =
        keccak256("quip.shrincs.action.markLeavesUsed");
    bytes32 internal constant ACTION_ERC1271 =
        keccak256("quip.shrincs.action.erc1271");

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

    /// @dev Domain separator committed inside the full-width V1 identity hash
    ///      (`v1Commitment`).
    bytes32 internal constant V1_IDENTITY_DOMAIN =
        keccak256("QUIP_SHRINCS_IDENTITY_V1");

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                 ERC-1271 ENVELOPE LAYOUT               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Fixed-layout ERC-1271 `signature`. No offsets, no padding; every size
    // derives from the compiled profile.
    //
    //   [0, 4)                     MAGIC       "QPCS"
    //   [4, 5)                     VERSION     StatelessLayout.ENCODING_VERSION
    //   [5, 37)                    PROFILE_ID  SHRINCSParams.PROFILE_ID
    //   [37, 102)                  ecdsaSig    owner ECDSA r ‖ s ‖ v
    //   [102, TOTAL_LEN)           payload     verifier stateless payload PK ‖ PQ
    //                                          (StatelessLayout.PAYLOAD_LEN bytes)
    //
    // `payload` is forwarded unchanged to the verifier's `verifyStateless`.
    // Decoded by `tryDecodeErc1271Signature` ("ERC-1271 ENVELOPE" below).

    /// @dev Envelope magic, ASCII "QPCS". Wallet-owned: it marks this envelope's own framing
    ///      (header, ECDSA slot), so a wallet-side layout change changes the magic.
    bytes4 internal constant ERC1271_MAGIC = 0x51504353;
    /// @dev Envelope encoding version: the upstream fixed-layout version of the `PK ‖ PQ`
    ///      payload, which `StatelessLayout` says the wallet envelope header carries.
    uint8 internal constant ERC1271_VERSION = StatelessLayout.ENCODING_VERSION;

    uint256 internal constant ERC1271_VERSION_OFF = 4; // bytes4 MAGIC
    uint256 internal constant ERC1271_PROFILE_OFF = ERC1271_VERSION_OFF + 1; // uint8 VERSION
    /// @dev MAGIC ‖ VERSION ‖ PROFILE_ID.
    uint256 internal constant ERC1271_HEADER_LEN = ERC1271_PROFILE_OFF + 32; // bytes32 PROFILE_ID
    uint256 internal constant ERC1271_ECDSA_OFF = ERC1271_HEADER_LEN;
    /// @dev Owner ECDSA `r ‖ s ‖ v`. No upstream or Solady constant exists for this width.
    uint256 internal constant ERC1271_ECDSA_LEN = 65;
    uint256 internal constant ERC1271_PAYLOAD_OFF =
        ERC1271_ECDSA_OFF + ERC1271_ECDSA_LEN;
    uint256 internal constant ERC1271_TOTAL_LEN =
        ERC1271_PAYLOAD_OFF + StatelessLayout.PAYLOAD_LEN;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    IDENTITY (V1)                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Full-width identity commitment binding both key commitments and the intended
    ///      owner. The version domain lives inside the hash preimage so all 256 output bits
    ///      retain second-preimage strength. Mirrors the SDK helper byte-for-byte.
    function v1Commitment(
        bytes32 statefulC,
        bytes32 statelessC,
        address owner
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(V1_IDENTITY_DOMAIN, statefulC, statelessC, owner)
            );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       DECODERS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Decodes the factory-supplied init payload, the ABI encoding of
    ///      `(bytes32 commitment, bytes32 pkSeed, PublicKey mainBundle, uint32 hashSuite,
    ///       PublicKey erc1271Bundle, uint32 erc1271HashSuite)`.
    ///      The ERC-1271 key travels as a FULL bundle (not a bare commitment) so the wallet
    ///      can derive its tree identities and record them in the lifetime spent-tree
    ///      registries: the dedicated 1271 key must never share a tree with the main key,
    ///      past or present, nor be reinstalled (INVARIANTS 23/25).
    ///      The payload is opaque to the factory; `commitment`/`pkSeed` landing at
    ///      `payload[0:32]` / `[32:64]` is just natural ABI head-word order, not a
    ///      layout constraint.
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
            SHRINCS.PublicKey calldata erc1271Bundle,
            uint32 erc1271HashSuite
        )
    {
        // Head is six 32-byte words (two are PublicKey tail offsets).
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
            // Solidity calldata accessors downstream, which bounds-check against calldatasize
            // (bare revert, not `MalformedPayload` — fail-closed, INVARIANTS §19).
            mainBundle := add(o, mbOff)
            hashSuite := and(calldataload(add(o, 0x60)), 0xffffffff)
            let ebOff := calldataload(add(o, 0x80))
            reqTail(ebOff, len, malformed)
            erc1271Bundle := add(o, ebOff)
            erc1271HashSuite := and(calldataload(add(o, 0xa0)), 0xffffffff)
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
            // through Solidity calldata accessors downstream, which bounds-check calldatasize
            // (bare revert, not `MalformedPayload`). `validateUserOp` runs this decoder and those
            // reads behind the `userOpEnvelope` self-staticcall, so the revert maps to a soft
            // fail there (INVARIANTS §19).
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
            // through Solidity calldata accessors downstream, which bounds-check calldatasize
            // (bare revert, not `MalformedPayload`). `validatePaymasterUserOp` runs this decoder
            // and those reads behind the `sponsorshipEnvelope` self-staticcall, so the revert
            // maps to a soft fail there (INVARIANTS §19).
            signature := add(o, sigOff)
        }
    }

    /// @dev Decodes the UUPS `upgradeToAndCall` `data` blob, the ABI encoding of
    ///      `(PublicKey publicKey, SHRINCS.Signature signature, bool shouldMigrate,
    ///       bytes migratorPayload, uint256 nonce, bytes probePayload)`. The action nonce the
    ///      signer bound rides in the blob so the wallet can assert exact freshness
    ///      (`StaleActionNonce` unless blob nonce == live nonce). The trailing
    ///      `migratorPayload` / `probePayload` are OPAQUE bytes for the NEW implementation
    ///      (the frozen `IWallet` seam) — this codec frames them, never interprets them.
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
            uint256 nonce,
            bytes calldata probePayload
        )
    {
        if (data.length < 0xc0) {
            revert MalformedPayload(0xc0, data.length);
        }
        bytes4 malformed = MalformedPayload.selector;
        assembly {
            let o := data.offset
            let len := data.length
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
            let pkOff := calldataload(o)
            reqTail(pkOff, len, malformed)
            publicKey := add(o, pkOff)
            let sigOff := calldataload(add(o, 0x20))
            reqTail(sigOff, len, malformed)
            // Nested PublicKey/Signature tail bounds are out of scope here; those fields are read
            // through Solidity calldata accessors downstream, which bounds-check calldatasize
            // (bare revert, not `MalformedPayload` — fail-closed, INVARIANTS §19).
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
            let po := calldataload(add(o, 0xa0))
            reqTail(po, len, malformed)
            let pLen := calldataload(add(o, po))
            // Same fit proof as migratorPayload: `po <= len - 0x20` was just proven, so
            // `sub(sub(len, 0x20), po)` cannot underflow — no wrapped-sum trust.
            if gt(pLen, sub(sub(len, 0x20), po)) {
                mstore(0x00, malformed)
                mstore(0x04, add(add(po, 0x20), pLen))
                mstore(0x24, len)
                revert(0x00, 0x44)
            }
            probePayload.offset := add(o, add(po, 0x20))
            probePayload.length := pLen
        }
    }

    /// @dev Decodes the SHRINCS `verifyUpgrade` probe vector (the frozen `IWallet` seam),
    ///      the ABI encoding of `(PublicKey bundle, SHRINCS.Signature statefulSig,
    ///      bytes statelessSig)`, where `statelessSig` is the fixed-layout PQ section
    ///      (`StatelessLayout.PQ_LEN` bytes; its length is checked by the verifier, not here).
    ///      The signed digest is not carried — it is recomputed on-chain via
    ///      `probeDigest(newImplementation)`.
    function decodeProbePayload(
        bytes calldata payload
    )
        internal
        pure
        returns (
            SHRINCS.PublicKey calldata bundle,
            SHRINCS.Signature calldata statefulSig,
            bytes calldata statelessSig
        )
    {
        // Head is three 32-byte words (all tail offsets).
        if (payload.length < 0x60) {
            revert MalformedPayload(0x60, payload.length);
        }
        bytes4 malformed = MalformedPayload.selector;
        assembly {
            let o := payload.offset
            let len := payload.length
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
            let bo := calldataload(o)
            reqTail(bo, len, malformed)
            // Nested struct tail bounds are out of scope here; those fields are read through
            // Solidity calldata accessors downstream, which bounds-check against calldatasize
            // (bare revert, not `MalformedPayload` — fail-closed, INVARIANTS §19).
            bundle := add(o, bo)
            let sfo := calldataload(add(o, 0x20))
            reqTail(sfo, len, malformed)
            statefulSig := add(o, sfo)
            let slo := calldataload(add(o, 0x40))
            reqTail(slo, len, malformed)
            let slLen := calldataload(add(o, slo))
            // The statelessSig bytes must fit: slo + 0x20 + slLen <= len. `slo <= len - 0x20`
            // was just proven, so `sub(sub(len, 0x20), slo)` cannot underflow.
            if gt(slLen, sub(sub(len, 0x20), slo)) {
                mstore(0x00, malformed)
                mstore(0x04, add(add(slo, 0x20), slLen))
                mstore(0x24, len)
                revert(0x00, 0x44)
            }
            statelessSig.offset := add(o, add(slo, 0x20))
            statelessSig.length := slLen
        }
    }

    /// @dev The digest a SHRINCS probe vector signs: the upgrade target address as a single
    ///      hashed word — binds the probe to `verifyUpgrade`'s `newImplementation`.
    function probeDigest(
        address newImplementation
    ) internal pure returns (bytes32) {
        return EfficientHashLib.hash(uint256(uint160(newImplementation)));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   STATELESS PAYLOAD                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Builds the verifier's stateless payload `PK ‖ PQ` (`StatelessLayout`) from an ABI
    ///      `PublicKey` and the fixed-layout PQ section, for the paths that also need the key
    ///      as a struct (rotation message hash, stateful half of the probe).
    ///      `PK = statefulPublicKey ‖ publicKeyCommitment ‖ pkSeed ‖ hypertreeRoot`.
    ///
    ///      `ok = false` when a key field has the wrong width. The verifier only checks the
    ///      payload's TOTAL length, so without this check mis-sized fields that sum to the right
    ///      width would be re-split at the fixed offsets; the verifier's commitment recompute
    ///      would still reject that, but the wallet does not rely on it. `pq`'s length is left
    ///      to the verifier (a wrong length returns its failure value).
    function tryEncodeStatelessPayload(
        SHRINCS.PublicKey calldata publicKey,
        bytes calldata pq
    ) internal pure returns (bool ok, bytes memory payload) {
        if (
            publicKey.statefulPublicKey.length !=
            SHRINCSParams.STATEFUL_PUBLIC_KEY_BYTES ||
            publicKey.publicKeyCommitment.length != 32 ||
            publicKey.pkSeed.length != 32 ||
            publicKey.hypertreeRoot.length != 32
        ) return (false, payload);
        return (
            true,
            abi.encodePacked(
                publicKey.statefulPublicKey,
                publicKey.publicKeyCommitment,
                publicKey.pkSeed,
                publicKey.hypertreeRoot,
                pq
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   ERC-1271 ENVELOPE                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Non-reverting decoder for the envelope laid out in "ERC-1271 ENVELOPE LAYOUT".
    ///      Non-reverting decoder for the ERC-1271 envelope, the staticcall path where a revert
    ///      is a denial of service on the relying contract. `ok` holds iff `sig` has the exact
    ///      envelope length and carries this build's magic, version and profile id. It never
    ///      inspects the payload (the verifier does) and reads only inside `sig`. On failure
    ///      both slices are empty.
    /// @return ok Whether `sig` is an envelope for this build.
    /// @return ecdsaSig The owner ECDSA half, `sig[ECDSA_OFF:PAYLOAD_OFF]`.
    /// @return payload The verifier stateless payload, `sig[PAYLOAD_OFF:]`.
    function tryDecodeErc1271Signature(
        bytes calldata sig
    )
        internal
        pure
        returns (bool ok, bytes calldata ecdsaSig, bytes calldata payload)
    {
        if (
            sig.length != ERC1271_TOTAL_LEN ||
            bytes4(sig[:ERC1271_VERSION_OFF]) != ERC1271_MAGIC ||
            uint8(sig[ERC1271_VERSION_OFF]) != ERC1271_VERSION ||
            bytes32(sig[ERC1271_PROFILE_OFF:ERC1271_HEADER_LEN]) !=
            SHRINCSParams.PROFILE_ID
        ) return (false, sig[0:0], sig[0:0]);
        return (
            true,
            sig[ERC1271_ECDSA_OFF:ERC1271_PAYLOAD_OFF],
            sig[ERC1271_PAYLOAD_OFF:]
        );
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
    ///      The incoming key's acceptance signs the same payload under the same action tag; the
    ///      two messages differ by the commitment they are bound to (installed vs. incoming).
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
}
