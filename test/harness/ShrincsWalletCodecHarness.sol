// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
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
            bytes32 erc1271Commitment,
            uint32 erc1271HashSuite
        )
    {
        (bytes32 _c, bytes32 _ps, SHRINCS.PublicKey calldata _mb, uint32 _hs, bytes32 _ec, uint32 _ehs) =
            Codec.decodeInit(payload);
        commitment = _c;
        pkSeed = _ps;
        mainBundle = _mb;
        hashSuite = _hs;
        erc1271Commitment = _ec;
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
            uint256 nonce
        )
    {
        (
            SHRINCS.PublicKey calldata _pk,
            SHRINCS.Signature calldata _sig,
            bool _m,
            bytes calldata _p,
            uint256 _n
        ) = Codec.decodeUpgradeAuth(data);
        publicKey = _pk;
        signature = _sig;
        shouldMigrate = _m;
        migratorPayload = _p;
        nonce = _n;
    }

    function exposed_tryDecodeErc1271Signature(bytes calldata sig)
        external
        pure
        returns (
            bool ok,
            SHRINCS.PublicKey memory publicKey,
            SPHINCSPlusC.Signature memory signature,
            bytes memory ecdsaSig
        )
    {
        SHRINCS.PublicKey calldata _pk;
        SPHINCSPlusC.Signature calldata _sig;
        bytes calldata _e;
        (ok, _pk, _sig, _e) = Codec.tryDecodeErc1271Signature(sig);
        // Mirror the production caller: on a malformed payload the calldata references are not
        // valid ABI and must not be dereferenced. Return the zero-value memory structs instead.
        if (!ok) return (ok, publicKey, signature, ecdsaSig);
        publicKey = _pk;
        signature = _sig;
        ecdsaSig = _e;
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
