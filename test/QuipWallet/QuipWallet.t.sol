// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory/QuipFactory.t.sol";
import {QuipWallet} from "../../contracts/QuipWallet.sol";
import {IQuipWallet} from "../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../contracts/WOTSPlusCodec.sol";

/// @title QuipWallet Base Test
/// @dev Base contract for testing QuipWallet. Inherits full stack from QuipFactoryTest
///      and deploys a wallet for ALICE.
contract QuipWalletTest is QuipFactoryTest {
    QuipWallet public wallet;
    /// @dev Primary active transaction key used by most tests (initially txn key 0).
    WOTSPlus.WinternitzAddress public alicePubkey;
    bytes32 public alicePrivateKey;
    /// @dev The full initial set of 5 transaction keys, for tests that need to access
    ///      more than one key at once (e.g. multi-key, addKeys(Transaction, …), drain).
    WOTSPlus.WinternitzAddress[5] public aliceTxnPubkeys;
    bytes32[5] public aliceTxnPrivkeys;
    WOTSPlus.WinternitzAddress[] public recoveryPubkeys;
    /// @dev Ownership WOTS+ keypair derived from `VAULT_SEED` via `_generateOwnershipKey`.
    ///      Mirrors the derivation used by `_createWalletFull` so `transferOwnership` /
    ///      `completeOwnershipHandover` tests can sign with the same material.
    WOTSPlus.WinternitzAddress public ownershipPubkey;
    bytes32 public ownershipPrivateKey;
    bytes32 public constant VAULT_SEED = "alice-vault-1";

    function setUp() public virtual override {
        super.setUp();

        // Deploy a wallet for ALICE with initial deposit
        (
            address walletAddr,
            WOTSPlus.WinternitzAddress[5] memory txnPubs,
            bytes32[5] memory txnPrivs,
            WOTSPlus.WinternitzAddress[] memory rPubkeys
        ) = _createWalletFull(ALICE, VAULT_SEED, INITIAL_DEPOSIT);
        wallet = QuipWallet(payable(walletAddr));
        for (uint256 i = 0; i < 5; i++) {
            aliceTxnPubkeys[i] = txnPubs[i];
            aliceTxnPrivkeys[i] = txnPrivs[i];
        }
        alicePubkey = txnPubs[0];
        alicePrivateKey = txnPrivs[0];

        for (uint256 i = 0; i < rPubkeys.length; i++) {
            recoveryPubkeys.push(rPubkeys[i]);
        }

        (ownershipPubkey, ownershipPrivateKey) = _generateOwnershipKey(
            VAULT_SEED
        );
    }

    function test_setUp() public view override {
        // Inherited checks
        assertEq(factory.owner(), ADMIN);

        // Wallet checks
        assertEq(wallet.owner(), ALICE);
        assertEq(address(wallet.quipFactory()), address(factory));
        assertEq(address(wallet).balance, INITIAL_DEPOSIT);

        // All 5 initial transaction keys are active
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 5);
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[i]));
        }

        // Recovery key checks
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
    }

    // --- Wallet-specific helpers ---

    function _buildExecuteMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        address target,
        uint256 value,
        bytes memory data,
        uint256 fee
    ) internal view returns (bytes32) {
        return
            Codec.executeDigest(
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                target,
                value,
                keccak256(data),
                fee
            );
    }

    function _buildChangePqOwnerMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory newPq
    ) internal view returns (bytes32) {
        return
            Codec.keyRotationDigest(
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                newPq.publicSeed,
                newPq.publicKeyHash
            );
    }

    function _buildRecoverWalletMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory recoveryKey,
        WOTSPlus.WinternitzAddress memory newRecoveryKey,
        WOTSPlus.WinternitzAddress memory newPq
    ) internal view returns (bytes32) {
        return
            Codec.recoverWalletDigest(
                wallet_,
                block.chainid,
                recoveryKey.publicSeed,
                recoveryKey.publicKeyHash,
                newRecoveryKey.publicSeed,
                newRecoveryKey.publicKeyHash,
                newPq.publicSeed,
                newPq.publicKeyHash
            );
    }

    function _buildAddRecoveryKeysMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) internal view returns (bytes32) {
        return
            Codec.keysetDigest(
                Codec.KeyType.Recovery,
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                keccak256(abi.encode(newKeys))
            );
    }

    function _buildReplenishRecoveryKeysMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) internal view returns (bytes32) {
        return
            Codec.keysetDigest(
                Codec.KeyType.Recovery,
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                keccak256(abi.encode(newKeys))
            );
    }

    function _buildTransferOwnershipMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        address newOwner,
        bytes32 keysHash
    ) internal view returns (bytes32) {
        return
            Codec.transferOwnershipDigest(
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                newOwner,
                keysHash
            );
    }

    function _buildCompleteOwnershipHandoverMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        address pendingOwner,
        bytes32 keysHash
    ) internal view returns (bytes32) {
        return
            Codec.completeOwnershipHandoverDigest(
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                pendingOwner,
                keysHash
            );
    }

    function _buildVerificationKeysMessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) internal view returns (bytes32) {
        return
            Codec.keysetDigest(
                Codec.KeyType.Verification,
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                keccak256(abi.encode(newKeys))
            );
    }

    function _buildReplaceKeyAtMessageHash(
        Codec.KeyType kind,
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        uint256 index,
        WOTSPlus.WinternitzAddress memory newKey
    ) internal view returns (bytes32) {
        return
            Codec.replaceKeyAtDigest(
                kind,
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                index,
                newKey.publicSeed,
                newKey.publicKeyHash
            );
    }

    function _buildErc1271MessageHash(
        address wallet_,
        WOTSPlus.WinternitzAddress memory verifier,
        bytes32 messageHash
    ) internal view returns (bytes32) {
        return
            Codec.erc1271Digest(
                wallet_,
                block.chainid,
                verifier.publicSeed,
                verifier.publicKeyHash,
                messageHash
            );
    }

    /// @dev Seeds the default `wallet`'s verificationKeys with `n` fresh keys by signing
    ///      an `addKeys(KeyType.Verification, …)` call with the current pqOwner. Rotates
    ///      `alicePubkey` / `alicePrivateKey` to a fresh pqOwner so downstream calls keep working.
    /// @return keys The generated Winternitz public keys now in the keys set.
    /// @return privateKeys Matching private keys for signing ERC-1271 messages.
    function _seedVerificationKeys(
        uint256 n
    )
        internal
        returns (
            WOTSPlus.WinternitzAddress[] memory keys,
            bytes32[] memory privateKeys
        )
    {
        keys = new WOTSPlus.WinternitzAddress[](n);
        privateKeys = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            bytes32 seed = keccak256(abi.encodePacked("vk-seed", i));
            (keys[i], privateKeys[i]) = _generateKeyPair(seed);
        }

        (
            WOTSPlus.WinternitzAddress memory nextPq,
            bytes32 nextPqKey
        ) = _generateKeyPair(
                keccak256(
                    abi.encodePacked(alicePrivateKey, "vk-seed-rotate", n)
                )
            );

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            keys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.addKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, keys)
        );

        alicePubkey = nextPq;
        alicePrivateKey = nextPqKey;
    }

    function _buildRecoveryUpgradeMessageHash(
        address wallet_,
        address newImplementation,
        WOTSPlus.WinternitzAddress memory currentRecoveryKey,
        WOTSPlus.WinternitzAddress memory newRecoveryKey
    ) internal view returns (bytes32) {
        return
            Codec.upgradeRecoveryDigest(
                wallet_,
                block.chainid,
                newImplementation,
                currentRecoveryKey.publicSeed,
                currentRecoveryKey.publicKeyHash,
                newRecoveryKey.publicSeed,
                newRecoveryKey.publicKeyHash
            );
    }
}
