// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EfficientHashLib} from "solady-0.1.26/src/utils/EfficientHashLib.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/wots/WOTSPlusCodec.sol";

contract WOTSPlusCodecHarness {
    // --- Decoders ---

    function exposed_decodeInit(bytes calldata payload)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory disasterRecoveryKey,
            WOTSPlus.WinternitzAddress memory ownershipKey,
            WOTSPlus.WinternitzAddress[10] memory transactionKeys,
            WOTSPlus.WinternitzAddress[10] memory recoveryKeys,
            WOTSPlus.WinternitzAddress[10] memory verificationKeys
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _dk,
            WOTSPlus.WinternitzAddress calldata _ok,
            WOTSPlus.WinternitzAddress[10] calldata _txn,
            WOTSPlus.WinternitzAddress[10] calldata _rec,
            WOTSPlus.WinternitzAddress[10] calldata _ver
        ) = Codec.decodeInit(payload);
        disasterRecoveryKey = _dk;
        ownershipKey = _ok;
        transactionKeys = _txn;
        recoveryKeys = _rec;
        verificationKeys = _ver;
    }

    function exposed_decodeUpgradeAuth(bytes calldata data)
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

    function exposed_decodeUpgradeVerification(bytes calldata data)
        external
        pure
        returns (WOTSPlus.WinternitzAddress memory verifier, WOTSPlus.WinternitzElements memory verifySig)
    {
        (WOTSPlus.WinternitzAddress calldata _v, WOTSPlus.WinternitzElements calldata _sig) =
            Codec.decodeUpgradeVerification(data);
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

    function exposed_decodeExecute(bytes calldata payload)
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

    // --- Encoders ---

    function exposed_encodeExecute(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address target,
        uint256 value,
        bytes memory data
    ) external pure returns (bytes memory) {
        return Codec.encodeExecute(currentKey, nextKey, pqSig, target, value, data);
    }

    // --- Hashers ---

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
        return Codec.executeDigest(wallet, chainId, s1, h1, s2, h2, target, value, opdataHash, fee);
    }

    function exposed_upgradeDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bool shouldMigrate,
        bytes32 migratorPayloadHash
    ) external pure returns (bytes32) {
        return
            Codec.upgradeDigest(
                wallet,
                chainId,
                newImplementation,
                s1,
                h1,
                s2,
                h2,
                shouldMigrate,
                migratorPayloadHash
            );
    }

    function exposed_verificationDigest(
        address wallet,
        uint256 chainId,
        address newImplementation,
        bytes32 s1,
        bytes32 h1
    ) external pure returns (bytes32) {
        return Codec.verificationDigest(wallet, chainId, newImplementation, s1, h1);
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
        return Codec.upgradeRecoveryDigest(
            wallet, chainId, newImplementation, currentSeed, currentHash, newSeed, newHash
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
        return Codec.withdrawDepositDigest(wallet, chainId, s1, h1, s2, h2, to, amount);
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
        return Codec.erc4337ExecuteDigest(wallet, chainId, s1, h1, s2, h2, userOpHash, fee);
    }

    // --- Decoders (additional) ---

    function exposed_decodeUserOpSignature(bytes calldata sig)
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

    function exposed_decodeWithdrawDeposit(bytes calldata payload)
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

    function exposed_decodeOwnershipTransfer(bytes calldata payload)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory currentOwnershipKey,
            WOTSPlus.WinternitzAddress memory newOwnershipKey,
            WOTSPlus.WinternitzElements memory pqSig,
            address newOwner,
            WOTSPlus.WinternitzAddress memory newDisasterKey,
            WOTSPlus.WinternitzAddress[10] memory newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys,
            WOTSPlus.WinternitzAddress[10] memory newVerificationKeys
        )
    {
        (currentOwnershipKey, newOwnershipKey, pqSig) = _decodeOwnershipAuth(payload);
        (newOwner, newDisasterKey, newTransactionKeys, newRecoveryKeys, newVerificationKeys) =
            _decodeOwnershipTail(payload);
    }

    function _decodeOwnershipAuth(bytes calldata payload)
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
            WOTSPlus.WinternitzElements calldata s,,,,,
        ) = Codec.decodeOwnershipTransfer(payload);
        return (c, n, s);
    }

    function _decodeOwnershipTail(bytes calldata payload)
        private
        pure
        returns (
            address,
            WOTSPlus.WinternitzAddress memory,
            WOTSPlus.WinternitzAddress[10] memory,
            WOTSPlus.WinternitzAddress[10] memory,
            WOTSPlus.WinternitzAddress[10] memory
        )
    {
        (
            ,,,
            address owner_,
            WOTSPlus.WinternitzAddress calldata dk,
            WOTSPlus.WinternitzAddress[10] calldata txn,
            WOTSPlus.WinternitzAddress[10] calldata rec,
            WOTSPlus.WinternitzAddress[10] calldata ver
        ) = Codec.decodeOwnershipTransfer(payload);
        return (owner_, dk, txn, rec, ver);
    }

    function exposed_encodeOwnershipTransfer(
        WOTSPlus.WinternitzAddress memory currentOwnershipKey,
        WOTSPlus.WinternitzAddress memory newOwnershipKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address newOwner,
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzAddress[10] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys,
        WOTSPlus.WinternitzAddress[10] memory newVerificationKeys
    ) external pure returns (bytes memory) {
        return Codec.encodeOwnershipTransfer(
            currentOwnershipKey,
            newOwnershipKey,
            pqSig,
            newOwner,
            newDisasterKey,
            newTransactionKeys,
            newRecoveryKeys,
            newVerificationKeys
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
        return Codec.transferOwnershipDigest(wallet, chainId, s1, h1, s2, h2, newOwner, keysHash);
    }

    // --- Decoders (recovery upgrade / save / replace / erc1271) ---

    function exposed_decodeSaveWallet(bytes calldata payload)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory currentDisasterKey,
            WOTSPlus.WinternitzAddress memory newDisasterKey,
            WOTSPlus.WinternitzElements memory pqSig,
            WOTSPlus.WinternitzAddress[10] memory newTransactionKeys,
            WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys,
            WOTSPlus.WinternitzAddress[10] memory newVerificationKeys
        )
    {
        (
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _n,
            WOTSPlus.WinternitzElements calldata _sig,
            WOTSPlus.WinternitzAddress[10] calldata _txn,
            WOTSPlus.WinternitzAddress[10] calldata _rec,
            WOTSPlus.WinternitzAddress[10] calldata _ver
        ) = Codec.decodeSaveWallet(payload);
        currentDisasterKey = _c;
        newDisasterKey = _n;
        pqSig = _sig;
        newTransactionKeys = _txn;
        newRecoveryKeys = _rec;
        newVerificationKeys = _ver;
    }

    function exposed_decodeRecoveryUpgradeAuth(bytes calldata data)
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

    function exposed_decodeRecoveryUpgradeVerification(bytes calldata data)
        external
        pure
        returns (WOTSPlus.WinternitzAddress memory verifier, WOTSPlus.WinternitzElements memory verifySig)
    {
        (WOTSPlus.WinternitzAddress calldata _v, WOTSPlus.WinternitzElements calldata _sig) =
            Codec.decodeRecoveryUpgradeVerification(data);
        verifier = _v;
        verifySig = _sig;
    }

    function exposed_decodeErc1271Signature(bytes calldata signature)
        external
        pure
        returns (
            WOTSPlus.WinternitzAddress memory verifier,
            WOTSPlus.WinternitzElements memory pqSig,
            bytes memory ecdsaSig
        )
    {
        (WOTSPlus.WinternitzAddress calldata _v, WOTSPlus.WinternitzElements calldata _sig, bytes calldata _e) =
            Codec.decodeErc1271Signature(signature);
        verifier = _v;
        pqSig = _sig;
        ecdsaSig = _e;
    }

    // --- Encoders (save / init / withdraw / replace / erc1271 / recovery / upgrade) ---

    function exposed_encodeSaveWallet(
        WOTSPlus.WinternitzAddress memory currentDisasterKey,
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[10] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys,
        WOTSPlus.WinternitzAddress[10] memory newVerificationKeys
    ) external pure returns (bytes memory) {
        return Codec.encodeSaveWallet(
            currentDisasterKey, newDisasterKey, pqSig, newTransactionKeys, newRecoveryKeys, newVerificationKeys
        );
    }

    function exposed_encodeInit(
        WOTSPlus.WinternitzAddress memory disasterRecoveryKey,
        WOTSPlus.WinternitzAddress memory ownershipKey,
        WOTSPlus.WinternitzAddress[10] memory transactionKeys,
        WOTSPlus.WinternitzAddress[10] memory recoveryKeys,
        WOTSPlus.WinternitzAddress[10] memory verificationKeys
    ) external pure returns (bytes memory) {
        return Codec.encodeInit(disasterRecoveryKey, ownershipKey, transactionKeys, recoveryKeys, verificationKeys);
    }

    function exposed_encodeWithdrawDeposit(
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        address to,
        uint256 amount
    ) external pure returns (bytes memory) {
        return Codec.encodeWithdrawDeposit(currentKey, nextKey, pqSig, to, amount);
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
        return Codec.encodeRecoveryUpgrade(currentRecoveryKey, newRecoveryKey, pqSig, verifier, verifySig);
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
        return Codec.encodeUpgradeToAndCall(
            currentKey, nextKey, pqSig, verifier, verifySig, shouldMigrate, migratorPayload
        );
    }

    // --- Hashers (erc1271 / saveWallet) ---

    function exposed_erc1271Digest(
        address wallet,
        uint256 chainId,
        bytes32 verifierSeed,
        bytes32 verifierHash,
        bytes32 messageHash
    ) external pure returns (bytes32) {
        return Codec.erc1271Digest(wallet, chainId, verifierSeed, verifierHash, messageHash);
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
        return Codec.saveWalletDigest(wallet, chainId, currentSeed, currentHash, newSeed, newHash, keysHash);
    }

    function exposed_saveWalletKeysHash(
        WOTSPlus.WinternitzAddress[10] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys,
        WOTSPlus.WinternitzAddress[10] memory newVerificationKeys
    ) external pure returns (bytes32) {
        return EfficientHashLib.hash(abi.encode(newTransactionKeys, newRecoveryKeys, newVerificationKeys));
    }

    function exposed_ownershipTransferKeysHash(
        WOTSPlus.WinternitzAddress memory newDisasterKey,
        WOTSPlus.WinternitzAddress[10] memory newTransactionKeys,
        WOTSPlus.WinternitzAddress[10] memory newRecoveryKeys,
        WOTSPlus.WinternitzAddress[10] memory newVerificationKeys
    ) external pure returns (bytes32) {
        return EfficientHashLib.hash(
            abi.encode(newDisasterKey, newTransactionKeys, newRecoveryKeys, newVerificationKeys)
        );
    }

    // --- replaceKeys ---

    /// @dev The 8-value return tuple from `Codec.decodeReplaceKeys` would
    ///      blow the stack budget if surfaced directly. Bundled into a struct
    ///      so callers receive one memory pointer.
    struct DecodedReplaceKeys {
        Codec.KeyType kind;
        Codec.KeyType signingKind;
        uint256 n;
        WOTSPlus.WinternitzAddress currentKey;
        WOTSPlus.WinternitzAddress nextKey;
        WOTSPlus.WinternitzElements pqSig;
        WOTSPlus.WinternitzAddress[] oldKeys;
        WOTSPlus.WinternitzAddress[] newKeys;
    }

    function exposed_decodeReplaceKeys(bytes calldata payload) external pure returns (DecodedReplaceKeys memory out) {
        (
            Codec.KeyType _k,
            Codec.KeyType _sk,
            uint256 _n,
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _nx,
            WOTSPlus.WinternitzElements calldata _sig,
            WOTSPlus.WinternitzAddress[] calldata _old,
            WOTSPlus.WinternitzAddress[] calldata _new
        ) = Codec.decodeReplaceKeys(payload);
        out.kind = _k;
        out.signingKind = _sk;
        out.n = _n;
        out.currentKey = _c;
        out.nextKey = _nx;
        out.pqSig = _sig;
        out.oldKeys = new WOTSPlus.WinternitzAddress[](_old.length);
        out.newKeys = new WOTSPlus.WinternitzAddress[](_new.length);
        for (uint256 i = 0; i < _old.length; i++) {
            out.oldKeys[i] = _old[i];
        }
        for (uint256 i = 0; i < _new.length; i++) {
            out.newKeys[i] = _new[i];
        }
    }

    function exposed_encodeReplaceKeys(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        uint256 n,
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[] memory oldKeys,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) external pure returns (bytes memory) {
        return Codec.encodeReplaceKeys(kind, signingKind, n, currentKey, nextKey, pqSig, oldKeys, newKeys);
    }

    function exposed_replaceKeysDigest(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        uint256 n,
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 oldKeysHash,
        bytes32 newKeysHash
    ) external pure returns (bytes32) {
        return Codec.replaceKeysDigest(kind, signingKind, n, wallet, chainId, s1, h1, s2, h2, oldKeysHash, newKeysHash);
    }

    /// @dev Bundles the decodeResetKeyset return into a single struct to keep
    ///      the harness ABI boundary stable across stack-pressure rebuilds.
    struct DecodedResetKeyset {
        Codec.KeyType kind;
        Codec.KeyType signingKind;
        WOTSPlus.WinternitzAddress currentKey;
        WOTSPlus.WinternitzAddress nextKey;
        WOTSPlus.WinternitzElements pqSig;
        WOTSPlus.WinternitzAddress[10] newKeys;
    }

    function exposed_decodeResetKeyset(bytes calldata payload) external pure returns (DecodedResetKeyset memory out) {
        (
            Codec.KeyType _k,
            Codec.KeyType _sk,
            WOTSPlus.WinternitzAddress calldata _c,
            WOTSPlus.WinternitzAddress calldata _nx,
            WOTSPlus.WinternitzElements calldata _sig,
            WOTSPlus.WinternitzAddress[10] calldata _new
        ) = Codec.decodeResetKeyset(payload);
        out.kind = _k;
        out.signingKind = _sk;
        out.currentKey = _c;
        out.nextKey = _nx;
        out.pqSig = _sig;
        for (uint256 i = 0; i < 10; i++) {
            out.newKeys[i] = _new[i];
        }
    }

    function exposed_encodeResetKeyset(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        WOTSPlus.WinternitzAddress memory currentKey,
        WOTSPlus.WinternitzAddress memory nextKey,
        WOTSPlus.WinternitzElements memory pqSig,
        WOTSPlus.WinternitzAddress[10] memory newKeys
    ) external pure returns (bytes memory) {
        return Codec.encodeResetKeyset(kind, signingKind, currentKey, nextKey, pqSig, newKeys);
    }

    function exposed_resetKeysetDigest(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        address wallet,
        uint256 chainId,
        bytes32 s1,
        bytes32 h1,
        bytes32 s2,
        bytes32 h2,
        bytes32 newKeysHash
    ) external pure returns (bytes32) {
        return Codec.resetKeysetDigest(kind, signingKind, wallet, chainId, s1, h1, s2, h2, newKeysHash);
    }
}
