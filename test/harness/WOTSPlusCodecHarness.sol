// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/WOTSPlusCodec.sol";

contract WOTSPlusCodecHarness {
    // --- Decoders ---

    function exposed_decodeInit(bytes calldata payload)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory pqOwner,
            WOTSPlus.WinternitzAddress[10] memory recoveryKeys
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _pq,
            WOTSPlus.WinternitzAddress[10] calldata _keys
        ) = Codec.decodeInit(payload);
        pqOwner = _pq;
        recoveryKeys = _keys;
    }

    function exposed_decodeUpgradeAuth(bytes calldata data)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory nextPqOwner,
            WOTSPlus.WinternitzElements memory pqSig
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _pq,
            WOTSPlus.WinternitzElements calldata _sig
        ) = Codec.decodeUpgradeAuth(data);
        nextPqOwner = _pq;
        pqSig = _sig;
    }

    function exposed_decodeUpgradeVerification(bytes calldata data)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory verifier,
            WOTSPlus.WinternitzElements memory verifySig
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _v,
            WOTSPlus.WinternitzElements calldata _sig
        ) = Codec.decodeUpgradeVerification(data);
        verifier = _v;
        verifySig = _sig;
    }

    function exposed_decodeUpgradeMigration(bytes calldata data)
        external
        pure
        returns (bool shouldMigrate, bytes memory migratorPayload)
    {
        (bool _m, bytes calldata _p) = Codec.decodeUpgradeMigration(data);
        shouldMigrate = _m;
        migratorPayload = _p;
    }

    function exposed_decodeChangePqOwner(bytes calldata payload)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory newPqOwner,
            WOTSPlus.WinternitzElements memory pqSig
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _pq,
            WOTSPlus.WinternitzElements calldata _sig
        ) = Codec.decodeChangePqOwner(payload);
        newPqOwner = _pq;
        pqSig = _sig;
    }

    function exposed_decodeExecute(bytes calldata payload)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory nextPqOwner,
            WOTSPlus.WinternitzElements memory pqSig,
            address target,
            uint256 value,
            bytes memory data
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _pq,
            WOTSPlus.WinternitzElements calldata _sig,
            address _t,
            uint256 _v,
            bytes calldata _d
        ) = Codec.decodeExecute(payload);
        nextPqOwner = _pq;
        pqSig = _sig;
        target = _t;
        value = _v;
        data = _d;
    }

    function exposed_decodeRecoverWallet(bytes calldata payload)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory recoveryKey,
            WOTSPlus.WinternitzAddress memory newPqOwner,
            WOTSPlus.WinternitzElements memory pqSig
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _rk,
            WOTSPlus.WinternitzAddress calldata _pq,
            WOTSPlus.WinternitzElements calldata _sig
        ) = Codec.decodeRecoverWallet(payload);
        recoveryKey = _rk;
        newPqOwner = _pq;
        pqSig = _sig;
    }

    function exposed_decodeKeyManagement(bytes calldata payload)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory nextPqOwner,
            WOTSPlus.WinternitzElements memory pqSig,
            WOTSPlus.WinternitzAddress[] memory newRecoveryKeys
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _pq,
            WOTSPlus.WinternitzElements calldata _sig,
            WOTSPlus.WinternitzAddress[] calldata _keys
        ) = Codec.decodeKeyManagement(payload);
        nextPqOwner = _pq;
        pqSig = _sig;
        newRecoveryKeys = new WOTSPlus.WinternitzAddress[](_keys.length);
        for (uint256 i = 0; i < _keys.length; i++) {
            newRecoveryKeys[i] = _keys[i];
        }
    }

    // --- Encoders ---

    function exposed_encodeChangePqOwner(
        WOTSPlus.WinternitzAddress memory newPqOwner,
        WOTSPlus.WinternitzElements memory pqSig
    ) external pure returns (bytes memory) {
        return Codec.encodeChangePqOwner(newPqOwner, pqSig);
    }

    function exposed_encodeExecute(
        WOTSPlus.WinternitzAddress memory nextPqOwner,
        WOTSPlus.WinternitzElements memory pqSig,
        address target,
        uint256 value,
        bytes memory data
    ) external pure returns (bytes memory) {
        return Codec.encodeExecute(nextPqOwner, pqSig, target, value, data);
    }

    function exposed_encodeRecoverWallet(
        WOTSPlus.WinternitzAddress memory recoveryKey,
        WOTSPlus.WinternitzAddress memory newPqOwner,
        WOTSPlus.WinternitzElements memory pqSig
    ) external pure returns (bytes memory) {
        return Codec.encodeRecoverWallet(recoveryKey, newPqOwner, pqSig);
    }

    function exposed_encodeKeyManagement(
        WOTSPlus.WinternitzAddress memory nextPqOwner,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[] memory newRecoveryKeys
    ) external pure returns (bytes memory) {
        return Codec.encodeKeyManagement(nextPqOwner, pqSig, newRecoveryKeys);
    }

    // --- Hashers ---

    function exposed_keyRotationDigest(
        address wallet, uint256 chainId,
        bytes32 s1, bytes32 h1, bytes32 s2, bytes32 h2
    ) external pure returns (bytes32) {
        return Codec.keyRotationDigest(wallet, chainId, s1, h1, s2, h2);
    }

    function exposed_executeDigest(
        address wallet, uint256 chainId,
        bytes32 s1, bytes32 h1, bytes32 s2, bytes32 h2,
        address target, uint256 value, bytes32 opdataHash
    ) external pure returns (bytes32) {
        return Codec.executeDigest(wallet, chainId, s1, h1, s2, h2, target, value, opdataHash);
    }

    function exposed_keyManagementDigest(
        address wallet, uint256 chainId,
        bytes32 s1, bytes32 h1, bytes32 s2, bytes32 h2,
        bytes32 keysHash
    ) external pure returns (bytes32) {
        return Codec.keyManagementDigest(wallet, chainId, s1, h1, s2, h2, keysHash);
    }

    function exposed_upgradeDigest(
        address wallet, uint256 chainId, address newImplementation,
        bytes32 s1, bytes32 h1, bytes32 s2, bytes32 h2
    ) external pure returns (bytes32) {
        return Codec.upgradeDigest(wallet, chainId, newImplementation, s1, h1, s2, h2);
    }

    function exposed_verificationDigest(
        address wallet, uint256 chainId, address newImplementation,
        bytes32 s1, bytes32 h1
    ) external pure returns (bytes32) {
        return Codec.verificationDigest(wallet, chainId, newImplementation, s1, h1);
    }
}
