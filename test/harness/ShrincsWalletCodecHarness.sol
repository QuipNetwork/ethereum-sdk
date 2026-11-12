// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.4.0/contracts/SHRINCS.sol";
import {ShrincsWalletCodec as Codec} from "../../contracts/shrincs/ShrincsWalletCodec.sol";

/// @dev Exposes the `ShrincsWalletCodec` library across an external boundary so its calldata
///      decoders, context builders, and payload-hash builders can be unit-tested.
contract ShrincsWalletCodecHarness {
    /* ─────────────────────────────── DECODERS ─────────────────────────────── */

    function exposed_decodeInit(bytes calldata payload)
        external
        pure
        returns (
            bytes32 commitment,
            bytes32 pkSeed,
            SHRINCS.PublicKey memory mainBundle,
            uint32 hashSuite,
            SHRINCS.PublicKey memory erc1271Bundle,
            uint32 erc1271HashSuite
        )
    {
        (
            bytes32 _c,
            bytes32 _ps,
            SHRINCS.PublicKey calldata _mb,
            uint32 _hs,
            SHRINCS.PublicKey calldata _eb,
            uint32 _ehs
        ) = Codec.decodeInit(payload);
        commitment = _c;
        pkSeed = _ps;
        mainBundle = _mb;
        hashSuite = _hs;
        erc1271Bundle = _eb;
        erc1271HashSuite = _ehs;
    }

    function exposed_decodeUserOpSignature(bytes calldata sig)
        external
        pure
        returns (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature,
            bytes memory ecdsaSig
        )
    {
        (SHRINCS.PublicKey calldata _pk, SHRINCS.Signature calldata _sig, bytes calldata _es) =
            Codec.decodeUserOpSignature(sig);
        publicKey = _pk;
        signature = _sig;
        ecdsaSig = _es;
    }

    function exposed_decodeSponsorshipSignature(bytes calldata sig)
        external
        pure
        returns (SHRINCS.PublicKey memory publicKey, SHRINCS.Signature memory signature)
    {
        (SHRINCS.PublicKey calldata _pk, SHRINCS.Signature calldata _sig) =
            Codec.decodeSponsorshipSignature(sig);
        publicKey = _pk;
        signature = _sig;
    }

    function exposed_decodeUpgradeAuth(bytes calldata data)
        external
        pure
        returns (
            SHRINCS.PublicKey memory publicKey,
            SHRINCS.Signature memory signature,
            bool shouldMigrate,
            bytes memory migratorPayload,
            uint256 nonce,
            bytes memory probePayload
        )
    {
        (
            SHRINCS.PublicKey calldata _pk,
            SHRINCS.Signature calldata _sig,
            bool _m,
            bytes calldata _p,
            uint256 _n,
            bytes calldata _pp
        ) = Codec.decodeUpgradeAuth(data);
        publicKey = _pk;
        signature = _sig;
        shouldMigrate = _m;
        migratorPayload = _p;
        nonce = _n;
        probePayload = _pp;
    }

    function exposed_decodeProbePayload(bytes calldata payload)
        external
        pure
        returns (
            SHRINCS.PublicKey memory bundle,
            SHRINCS.Signature memory statefulSig,
            bytes memory statelessSig
        )
    {
        (
            SHRINCS.PublicKey calldata _b,
            SHRINCS.Signature calldata _sf,
            bytes calldata _sl
        ) = Codec.decodeProbePayload(payload);
        bundle = _b;
        statefulSig = _sf;
        statelessSig = _sl;
    }

    function exposed_tryEncodeStatelessPayload(SHRINCS.PublicKey calldata publicKey, bytes calldata pq)
        external
        pure
        returns (bool ok, bytes memory payload)
    {
        return Codec.tryEncodeStatelessPayload(publicKey, pq);
    }

    function exposed_tryDecodeErc1271Signature(bytes calldata sig)
        external
        pure
        returns (bool ok, bytes memory ecdsaSig, bytes memory payload)
    {
        bytes calldata _e;
        bytes calldata _p;
        (ok, _e, _p) = Codec.tryDecodeErc1271Signature(sig);
        ecdsaSig = _e;
        payload = _p;
    }

    /* ────────────────────────── CONTEXT BUILDERS ───────────────────────────── */

    function exposed_buildActionContext(
        bytes32 domainSeparator,
        uint256 nonce,
        uint256 keyVersion,
        bytes32 actionType,
        bytes32 payloadHash
    ) external pure returns (SHRINCS.ActionContext memory) {
        return Codec.buildActionContext(domainSeparator, nonce, keyVersion, actionType, payloadHash);
    }

    function exposed_buildRotationContext(bytes32 domainSeparator, uint256 nonce, uint256 keyVersion)
        external
        pure
        returns (SHRINCS.RotationContext memory)
    {
        return Codec.buildRotationContext(domainSeparator, nonce, keyVersion);
    }

    function exposed_rotationDomainSeparator(bytes32 base, bytes32 tag) external pure returns (bytes32) {
        return Codec.rotationDomainSeparator(base, tag);
    }

    /* ─────────────────────────── PAYLOAD HASHES ────────────────────────────── */

    function exposed_erc4337PayloadHash(bytes32 userOpHash) external pure returns (bytes32) {
        return Codec.erc4337PayloadHash(userOpHash);
    }

    function exposed_executePayloadHash(address target, uint256 value, bytes32 dataHash, uint256 maxFee)
        external
        pure
        returns (bytes32)
    {
        return Codec.executePayloadHash(target, value, dataHash, maxFee);
    }

    function exposed_withdrawPayloadHash(address to, uint256 amount) external pure returns (bytes32) {
        return Codec.withdrawPayloadHash(to, amount);
    }

    function exposed_upgradePayloadHash(address newImplementation, bool shouldMigrate, bytes32 migratorHash)
        external
        pure
        returns (bytes32)
    {
        return Codec.upgradePayloadHash(newImplementation, shouldMigrate, migratorHash);
    }

    function exposed_transferOwnershipPayloadHash(address newOwner, bytes32 nextCommitment)
        external
        pure
        returns (bytes32)
    {
        return Codec.transferOwnershipPayloadHash(newOwner, nextCommitment);
    }

    function exposed_setErc1271KeyPayloadHash(bytes32 newCommitment, uint32 newHashSuite)
        external
        pure
        returns (bytes32)
    {
        return Codec.setErc1271KeyPayloadHash(newCommitment, newHashSuite);
    }

    function exposed_rotateKeyPayloadHash(bytes32 nextCommitment) external pure returns (bytes32) {
        return Codec.rotateKeyPayloadHash(nextCommitment);
    }

    function exposed_markLeavesUsedPayloadHash(bytes32 leavesHash) external pure returns (bytes32) {
        return Codec.markLeavesUsedPayloadHash(leavesHash);
    }
}
