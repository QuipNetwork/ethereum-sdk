// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/WOTSPlusCodec.sol";

contract WOTSPlusCodecHarness {
    // --- Decoders ---

    function exposed_decodeInit(
        bytes calldata payload
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory disasterRecoveryKey,
            WOTSPlus.WinternitzAddress memory ownershipKey,
            WOTSPlus.WinternitzAddress[5] memory transactionKeys,
            WOTSPlus.WinternitzAddress[10] memory recoveryKeys
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _dk,
            WOTSPlus.WinternitzAddress calldata _ok,
            WOTSPlus.WinternitzAddress[5] calldata _txn,
            WOTSPlus.WinternitzAddress[10] calldata _keys
        ) = Codec.decodeInit(payload);
        disasterRecoveryKey = _dk;
        ownershipKey = _ok;
        transactionKeys = _txn;
        recoveryKeys = _keys;
    }

    function exposed_decodeUpgradeAuth(
        bytes calldata data
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory currentKey,
            WOTSPlus.WinternitzAddress memory nextKey,
            WOTSPlus.WinternitzElements memory pqSig
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _n,
            WOTSPlus.WinternitzElements calldata _sig
        ) = Codec.decodeUpgradeAuth(data);
        currentKey = _c;
        nextKey = _n;
        pqSig = _sig;
    }

    function exposed_decodeUpgradeVerification(
        bytes calldata data
    )
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

    function exposed_decodeUpgradeMigration(
        bytes calldata data
    ) external pure returns (bool shouldMigrate, bytes memory migratorPayload) {
        (bool _m, bytes calldata _p) = Codec.decodeUpgradeMigration(data);
        shouldMigrate = _m;
        migratorPayload = _p;
    }

    function exposed_decodeExecute(
        bytes calldata payload
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory currentKey,
            WOTSPlus.WinternitzAddress memory nextKey,
            WOTSPlus.WinternitzElements memory pqSig,
            address target,
            uint256 value,
            bytes memory data
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _n,
            WOTSPlus.WinternitzElements calldata _sig,
            address _t,
            uint256 _v,
            bytes calldata _d
        ) = Codec.decodeExecute(payload);
        currentKey = _c;
        nextKey = _n;
        pqSig = _sig;
        target = _t;
        value = _v;
        data = _d;
    }

    function exposed_decodeRecoverWallet(
        bytes calldata payload
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory recoveryKey,
            WOTSPlus.WinternitzAddress memory newRecoveryKey,
            WOTSPlus.WinternitzAddress memory newTransactionKey,
            WOTSPlus.WinternitzElements memory pqSig
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _rk,
            WOTSPlus.WinternitzAddress calldata _newRk,
            WOTSPlus.WinternitzAddress calldata _pq,
            WOTSPlus.WinternitzElements calldata _sig
        ) = Codec.decodeRecoverWallet(payload);
        recoveryKey = _rk;
        newRecoveryKey = _newRk;
        newTransactionKey = _pq;
        pqSig = _sig;
    }

    function exposed_decodeKeyManagement(
        bytes calldata payload
    )
        external
        pure
        returns (
            Codec.KeyType kind,
            WOTSPlus.WinternitzAddress memory currentKey,
            WOTSPlus.WinternitzAddress memory nextKey,
            WOTSPlus.WinternitzElements memory pqSig,
            WOTSPlus.WinternitzAddress[] memory newKeys
        )
    {
        (
            Codec.KeyType _k,
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _n,
            WOTSPlus.WinternitzElements calldata _sig,
            WOTSPlus.WinternitzAddress[] calldata _keys
        ) = Codec.decodeKeyManagement(payload);
        kind = _k;
        currentKey = _c;
        nextKey = _n;
        pqSig = _sig;
        newKeys = new WOTSPlus.WinternitzAddress[](_keys.length);
        for (uint256 i = 0; i < _keys.length; i++) {
            newKeys[i] = _keys[i];
        }
    }

    // --- Encoders ---

    function exposed_encodeExecute(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address target,
        uint256 value,
        bytes memory data
    ) external pure returns (bytes memory) {
        return
            Codec.encodeExecute(
                currentKey,
                nextKey,
                pqSig,
                target,
                value,
                data
            );
    }

    function exposed_encodeRecoverWallet(
        WOTSPlus.WinternitzAddress memory recoveryKey,
        WOTSPlus.WinternitzAddress memory newRecoveryKey,
        WOTSPlus.WinternitzAddress memory newTransactionKey,
        WOTSPlus.WinternitzElements memory pqSig
    ) external pure returns (bytes memory) {
        return
            Codec.encodeRecoverWallet(
                recoveryKey,
                newRecoveryKey,
                newTransactionKey,
                pqSig
            );
    }

    function exposed_encodeKeyManagement(
        Codec.KeyType kind,
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) external pure returns (bytes memory) {
        return
            Codec.encodeKeyManagement(
                kind,
                currentKey,
                nextKey,
                pqSig,
                newKeys
            );
    }

    // --- Hashers ---

    function exposed_recoverWalletDigest(
        address wallet,
        uint256 chainId,
        bytes32 recoverySeed,
        bytes32 recoveryHash,
        bytes32 newRecoverySeed,
        bytes32 newRecoveryHash,
        bytes32 newTransactionSeed,
        bytes32 newTransactionHash
    ) external pure returns (bytes32) {
        return
            Codec.recoverWalletDigest(
                wallet,
                chainId,
                recoverySeed,
                recoveryHash,
                newRecoverySeed,
                newRecoveryHash,
                newTransactionSeed,
                newTransactionHash
            );
    }

    function exposed_executeDigest(
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
    ) external pure returns (bytes32) {
        return
            Codec.executeDigest(
                wallet,
                chainId,
                s1,
                h1,
                s2,
                h2,
                target,
                value,
                opdataHash,
                fee
            );
    }

    function exposed_keysetDigest(
        Codec.KeyType kind,
        bool replace,
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 keysHash
    ) external pure returns (bytes32) {
        return
            Codec.keysetDigest(
                kind,
                replace,
                wallet,
                chainId,
                s1,
                h1,
                s2,
                h2,
                keysHash
            );
    }

    function exposed_upgradeDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2
    ) external pure returns (bytes32) {
        return
            Codec.upgradeDigest(
                wallet,
                chainId,
                newImplementation,
                s1,
                h1,
                s2,
                h2
            );
    }

    function exposed_verificationDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1
    ) external pure returns (bytes32) {
        return
            Codec.verificationDigest(
                wallet,
                chainId,
                newImplementation,
                s1,
                h1
            );
    }

    function exposed_upgradeRecoveryDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 currentSeed,
        bytes32 currentHash,
        bytes32 newSeed,
        bytes32 newHash
    ) external pure returns (bytes32) {
        return
            Codec.upgradeRecoveryDigest(
                wallet,
                chainId,
                newImplementation,
                currentSeed,
                currentHash,
                newSeed,
                newHash
            );
    }

    function exposed_withdrawDepositDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address to,
        uint256 amount
    ) external pure returns (bytes32) {
        return
            Codec.withdrawDepositDigest(
                wallet,
                chainId,
                s1,
                h1,
                s2,
                h2,
                to,
                amount
            );
    }

    function exposed_erc4337ExecuteDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 userOpHash,
        uint256 fee
    ) external pure returns (bytes32) {
        return
            Codec.erc4337ExecuteDigest(
                wallet,
                chainId,
                s1,
                h1,
                s2,
                h2,
                userOpHash,
                fee
            );
    }

    // --- Decoders (additional) ---

    function exposed_decodeUserOpSignature(
        bytes calldata sig
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory currentKey,
            WOTSPlus.WinternitzAddress memory nextKey,
            WOTSPlus.WinternitzElements memory pqSig
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _n,
            WOTSPlus.WinternitzElements calldata _sig
        ) = Codec.decodeUserOpSignature(sig);
        currentKey = _c;
        nextKey = _n;
        pqSig = _sig;
    }

    function exposed_decodeWithdrawDeposit(
        bytes calldata payload
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory currentKey,
            WOTSPlus.WinternitzAddress memory nextKey,
            WOTSPlus.WinternitzElements memory pqSig,
            address to,
            uint256 amount
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _n,
            WOTSPlus.WinternitzElements calldata _sig,
            address _to,
            uint256 _amt
        ) = Codec.decodeWithdrawDeposit(payload);
        currentKey = _c;
        nextKey = _n;
        pqSig = _sig;
        to = _to;
        amount = _amt;
    }

    // --- Encoders (additional) ---

    function exposed_encodeUserOpSignature(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig
    ) external pure returns (bytes memory) {
        return Codec.encodeUserOpSignature(currentKey, nextKey, pqSig);
    }

    function exposed_decodeOwnershipTransfer(
        bytes calldata payload
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory currentOwnershipKey,
            WOTSPlus.WinternitzAddress memory newOwnershipKey,
            WOTSPlus.WinternitzElements memory pqSig,
            address newOwner,
            WOTSPlus.WinternitzAddress memory newDisasterKey,
            WOTSPlus.WinternitzAddress[5] memory newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys
        )
    {
        (currentOwnershipKey, newOwnershipKey, pqSig) = _decodeOwnershipAuth(
            payload
        );
        (
            newOwner,
            newDisasterKey,
            newTransactionKeys,
            newRecoveryKeys
        ) = _decodeOwnershipTail(payload);
    }

    function _decodeOwnershipAuth(
        bytes calldata payload
    )
        private
        pure
        returns (
            WOTSPlus.WinternitzAddress memory,
            WOTSPlus.WinternitzAddress memory,
            WOTSPlus.WinternitzElements memory
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata c,
            WOTSPlus.WinternitzAddress calldata n,
            WOTSPlus.WinternitzElements calldata s,
            ,
            ,
            ,

        ) = Codec.decodeOwnershipTransfer(payload);
        return (c, n, s);
    }

    function _decodeOwnershipTail(
        bytes calldata payload
    )
        private
        pure
        returns (
            address,
            WOTSPlus.WinternitzAddress memory,
            WOTSPlus.WinternitzAddress[5] memory,
            WOTSPlus.WinternitzAddress[10] memory
        )
    {
        (
            ,
            ,
            ,
            address owner_,
            WOTSPlus.WinternitzAddress calldata dk,
            WOTSPlus.WinternitzAddress[5] calldata txn,
            WOTSPlus.WinternitzAddress[10] calldata rec
        ) = Codec.decodeOwnershipTransfer(payload);
        return (owner_, dk, txn, rec);
    }

    function exposed_encodeOwnershipTransfer(
        WOTSPlus.WinternitzAddress memory currentOwnershipKey,
        WOTSPlus.WinternitzAddress memory newOwnershipKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address newOwner,
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzAddress[5] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys
    ) external pure returns (bytes memory) {
        return
            Codec.encodeOwnershipTransfer(
                currentOwnershipKey,
                newOwnershipKey,
                pqSig,
                newOwner,
                newDisasterKey,
                newTransactionKeys,
                newRecoveryKeys
            );
    }

    function exposed_transferOwnershipDigest(
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        address newOwner,
        bytes32 keysHash
    ) external pure returns (bytes32) {
        return
            Codec.transferOwnershipDigest(
                wallet,
                chainId,
                s1,
                h1,
                s2,
                h2,
                newOwner,
                keysHash
            );
    }

    // --- Decoders (recovery upgrade / save / replace / erc1271) ---

    function exposed_decodeSaveWallet(
        bytes calldata payload
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory currentDisasterKey,
            WOTSPlus.WinternitzAddress memory newDisasterKey,
            WOTSPlus.WinternitzElements memory pqSig,
            WOTSPlus.WinternitzAddress[5] memory newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _n,
            WOTSPlus.WinternitzElements calldata _sig,
            WOTSPlus.WinternitzAddress[5] calldata _txn,
            WOTSPlus.WinternitzAddress[10] calldata _rec
        ) = Codec.decodeSaveWallet(payload);
        currentDisasterKey = _c;
        newDisasterKey = _n;
        pqSig = _sig;
        newTransactionKeys = _txn;
        newRecoveryKeys = _rec;
    }

    function exposed_decodeRecoveryUpgradeAuth(
        bytes calldata data
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory currentRecoveryKey,
            WOTSPlus.WinternitzAddress memory newRecoveryKey,
            WOTSPlus.WinternitzElements memory pqSig
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _n,
            WOTSPlus.WinternitzElements calldata _sig
        ) = Codec.decodeRecoveryUpgradeAuth(data);
        currentRecoveryKey = _c;
        newRecoveryKey = _n;
        pqSig = _sig;
    }

    function exposed_decodeRecoveryUpgradeVerification(
        bytes calldata data
    )
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
        ) = Codec.decodeRecoveryUpgradeVerification(data);
        verifier = _v;
        verifySig = _sig;
    }

    function exposed_decodeReplaceKeyAt(
        bytes calldata payload
    )
        external
        pure
        returns (
            Codec.KeyType kind,
            WOTSPlus.WinternitzAddress memory currentKey,
            WOTSPlus.WinternitzAddress memory nextKey,
            WOTSPlus.WinternitzElements memory pqSig,
            uint256 index,
            WOTSPlus.WinternitzAddress memory newKey
        )
    {
        (
            Codec.KeyType _k,
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _n,
            WOTSPlus.WinternitzElements calldata _sig,
            uint256 _i,
            WOTSPlus.WinternitzAddress calldata _nk
        ) = Codec.decodeReplaceKeyAt(payload);
        kind = _k;
        currentKey = _c;
        nextKey = _n;
        pqSig = _sig;
        index = _i;
        newKey = _nk;
    }

    function exposed_decodeErc1271Signature(
        bytes calldata signature
    )
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory verifier,
            WOTSPlus.WinternitzElements memory pqSig,
            bytes memory ecdsaSig
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _v,
            WOTSPlus.WinternitzElements calldata _sig,
            bytes calldata _e
        ) = Codec.decodeErc1271Signature(signature);
        verifier = _v;
        pqSig = _sig;
        ecdsaSig = _e;
    }

    // --- Encoders (save / init / withdraw / replace / erc1271 / recovery / upgrade) ---

    function exposed_encodeSaveWallet(
        WOTSPlus.WinternitzAddress memory currentDisasterKey,
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[5] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys
    ) external pure returns (bytes memory) {
        return
            Codec.encodeSaveWallet(
                currentDisasterKey,
                newDisasterKey,
                pqSig,
                newTransactionKeys,
                newRecoveryKeys
            );
    }

    function exposed_encodeInit(
        WOTSPlus.WinternitzAddress memory disasterRecoveryKey,
        WOTSPlus.WinternitzAddress memory ownershipKey,
        WOTSPlus.WinternitzAddress[5] memory transactionKeys,
        WOTSPlus.WinternitzAddress[10] memory recoveryKeys
    ) external pure returns (bytes memory) {
        return
            Codec.encodeInit(
                disasterRecoveryKey,
                ownershipKey,
                transactionKeys,
                recoveryKeys
            );
    }

    function exposed_encodeWithdrawDeposit(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address to,
        uint256 amount
    ) external pure returns (bytes memory) {
        return
            Codec.encodeWithdrawDeposit(
                currentKey,
                nextKey,
                pqSig,
                to,
                amount
            );
    }

    function exposed_encodeReplaceKeyAt(
        Codec.KeyType kind,
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        uint256 index,
        WOTSPlus.WinternitzAddress memory newKey
    ) external pure returns (bytes memory) {
        return
            Codec.encodeReplaceKeyAt(
                kind,
                currentKey,
                nextKey,
                pqSig,
                index,
                newKey
            );
    }

    function exposed_encodeErc1271Signature(
        WOTSPlus.WinternitzAddress memory verifier,
        WOTSPlus.WinternitzElements memory pqSig,
        bytes memory ecdsaSig
    ) external pure returns (bytes memory) {
        return Codec.encodeErc1271Signature(verifier, pqSig, ecdsaSig);
    }

    function exposed_encodeRecoveryUpgrade(
        WOTSPlus.WinternitzAddress memory currentRecoveryKey,
        WOTSPlus.WinternitzAddress memory newRecoveryKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress memory verifier,
        WOTSPlus.WinternitzElements memory verifySig
    ) external pure returns (bytes memory) {
        return
            Codec.encodeRecoveryUpgrade(
                currentRecoveryKey,
                newRecoveryKey,
                pqSig,
                verifier,
                verifySig
            );
    }

    function exposed_encodeUpgradeToAndCall(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress memory verifier,
        WOTSPlus.WinternitzElements memory verifySig,
        bool shouldMigrate,
        bytes memory migratorPayload
    ) external pure returns (bytes memory) {
        return
            Codec.encodeUpgradeToAndCall(
                currentKey,
                nextKey,
                pqSig,
                verifier,
                verifySig,
                shouldMigrate,
                migratorPayload
            );
    }

    // --- Hashers (replace / erc1271 / saveWallet) ---

    function exposed_replaceKeyAtDigest(
        Codec.KeyType kind,
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        uint256 index,
        bytes32 newSeed,
        bytes32 newHash
    ) external pure returns (bytes32) {
        return
            Codec.replaceKeyAtDigest(
                kind,
                wallet,
                chainId,
                s1,
                h1,
                s2,
                h2,
                index,
                newSeed,
                newHash
            );
    }

    function exposed_erc1271Digest(
        address wallet,
        uint256 chainId,
        bytes32 verifierSeed,
        bytes32 verifierHash,
        bytes32 messageHash
    ) external pure returns (bytes32) {
        return
            Codec.erc1271Digest(
                wallet,
                chainId,
                verifierSeed,
                verifierHash,
                messageHash
            );
    }

    function exposed_saveWalletDigest(
        address wallet,
        uint256 chainId,
        bytes32 currentSeed,
        bytes32 currentHash,
        bytes32 newSeed,
        bytes32 newHash,
        bytes32 keysHash
    ) external pure returns (bytes32) {
        return
            Codec.saveWalletDigest(
                wallet,
                chainId,
                currentSeed,
                currentHash,
                newSeed,
                newHash,
                keysHash
            );
    }

    function exposed_saveWalletKeysHash(
        WOTSPlus.WinternitzAddress[5] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys
    ) external pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                abi.encode(newTransactionKeys, newRecoveryKeys)
            );
    }

    function exposed_ownershipTransferKeysHash(
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzAddress[5] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys
    ) external pure returns (bytes32) {
        return
            EfficientHashLib.hash(
                abi.encode(newDisasterKey, newTransactionKeys, newRecoveryKeys)
            );
    }
}
