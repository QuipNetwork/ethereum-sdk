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
    ///      more than one key at once (e.g. multi-key swap via replaceKeys, drain).
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

    function _buildReplaceKeysMessageHash(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[] memory oldKeys,
        WOTSPlus.WinternitzAddress[] memory newKeys
    ) internal view returns (bytes32) {
        return
            Codec.replaceKeysDigest(
                kind,
                signingKind,
                oldKeys.length,
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                keccak256(abi.encode(oldKeys)),
                keccak256(abi.encode(newKeys))
            );
    }

    function _buildResetKeysetMessageHash(
        Codec.KeyType kind,
        Codec.KeyType signingKind,
        address wallet_,
        WOTSPlus.WinternitzAddress memory currentPq,
        WOTSPlus.WinternitzAddress memory nextPq,
        WOTSPlus.WinternitzAddress[10] memory newKeys
    ) internal view returns (bytes32) {
        return
            Codec.resetKeysetDigest(
                kind,
                signingKind,
                wallet_,
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                keccak256(abi.encode(newKeys))
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

    /// @dev Seeds the default `wallet`'s verificationKeys via `resetKeyset` —
    ///      the always-10 invariant means we always install exactly 10 fresh
    ///      keys on each call, regardless of `n`. Returns the first `n` of
    ///      them so existing callers that asked for `_seedVerificationKeys(k)`
    ///      get a `k`-length pair of pubkey/privkey arrays without rewriting.
    ///      Rotates `alicePubkey` / `alicePrivateKey` to a fresh tx key so
    ///      downstream calls keep working.
    /// @return keys The first `n` Winternitz pubkeys installed in the set.
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
        WOTSPlus.WinternitzAddress[10] memory all10;
        bytes32[10] memory priv10;
        for (uint256 i = 0; i < 10; i++) {
            bytes32 seed = keccak256(
                abi.encodePacked("vk-seed", alicePrivateKey, i)
            );
            (all10[i], priv10[i]) = _generateKeyPair(seed);
        }

        (
            WOTSPlus.WinternitzAddress memory nextPq,
            bytes32 nextPqKey
        ) = _generateKeyPair(
                keccak256(
                    abi.encodePacked(alicePrivateKey, "vk-seed-rotate", n)
                )
            );

        bytes32 msgHash = _buildResetKeysetMessageHash(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            address(wallet),
            alicePubkey,
            nextPq,
            all10
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                Codec.KeyType.Verification,
                Codec.KeyType.Transaction,
                alicePubkey,
                nextPq,
                sig,
                all10
            )
        );

        alicePubkey = nextPq;
        alicePrivateKey = nextPqKey;

        keys = new WOTSPlus.WinternitzAddress[](n);
        privateKeys = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            keys[i] = all10[i];
            privateKeys[i] = priv10[i];
        }
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

    /// @dev Builds the full upgrade data payload (5441 bytes) for `upgradeToAndCall`.
    ///      Layout: [0:64) currentKey, [64:128) nextKey, [128:2272) pqSig,
    ///              [2272:2336) verifier, [2336:4480) verifySig,
    ///              [4480] shouldMigrate, [4481:5441) migratorPayload.
    function _buildUpgradeData(
        address newImplementation_,
        bytes32 signingKey,
        WOTSPlus.WinternitzAddress memory currentPqOwner,
        WOTSPlus.WinternitzAddress memory nextPqOwner,
        bytes32 verifierSeed,
        bool shouldMigrate,
        WOTSPlus.WinternitzAddress memory migratePqOwner,
        WOTSPlus.WinternitzAddress[] memory migrateRecoveryKeys
    ) internal view returns (bytes memory) {
        bytes32 digest = Codec.upgradeDigest(
            address(wallet),
            block.chainid,
            address(newImplementation_),
            currentPqOwner.publicSeed,
            currentPqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash
        );

        WOTSPlus.WinternitzElements memory sig = _sign(signingKey, digest);

        bytes memory keyHeader = abi.encodePacked(
            currentPqOwner.publicSeed,
            currentPqOwner.publicKeyHash,
            nextPqOwner.publicSeed,
            nextPqOwner.publicKeyHash
        );

        bytes memory pqSig;
        for (uint256 i = 0; i < 67; i++) {
            pqSig = abi.encodePacked(pqSig, sig.elements[i]);
        }

        bytes memory verifierData = _buildUpgradeVerifierBytes(
            newImplementation_,
            verifierSeed
        );

        bytes memory migrateFlag = abi.encodePacked(
            shouldMigrate ? uint8(1) : uint8(0)
        );

        WOTSPlus.WinternitzAddress[]
            memory recKeys = new WOTSPlus.WinternitzAddress[](10);
        for (uint256 i = 0; i < 10; i++) {
            if (i < migrateRecoveryKeys.length) {
                recKeys[i] = migrateRecoveryKeys[i];
            } else {
                recKeys[i] = WOTSPlus.WinternitzAddress({
                    publicSeed: bytes32(uint256(i + 1)),
                    publicKeyHash: bytes32(uint256(i + 100))
                });
            }
        }
        bytes memory migratorPayload = _encodeInitPayload(
            migratePqOwner,
            recKeys
        );

        return
            abi.encodePacked(
                keyHeader,
                pqSig,
                verifierData,
                migrateFlag,
                migratorPayload
            );
    }

    /// @dev Builds the verifier portion of an upgrade payload: 64-byte verifier
    ///      pubkey + 2144-byte WOTS+ signature over the verification digest,
    ///      packed for `abi.encodePacked` insertion into the upgrade calldata.
    ///      Distinct from the scenario tests' `_buildVerifierData` which
    ///      returns the (vPub, vSig) tuple unpacked.
    function _buildUpgradeVerifierBytes(
        address newImplementation_,
        bytes32 verifierSeed
    ) internal view returns (bytes memory) {
        (
            WOTSPlus.WinternitzAddress memory vPub,
            bytes32 vPriv
        ) = _generateKeyPair(verifierSeed);
        bytes32 vHash = Codec.verificationDigest(
            address(wallet),
            block.chainid,
            newImplementation_,
            vPub.publicSeed,
            vPub.publicKeyHash
        );
        WOTSPlus.WinternitzElements memory vSig = _sign(vPriv, vHash);

        bytes memory data = abi.encodePacked(
            vPub.publicSeed,
            vPub.publicKeyHash
        );
        for (uint256 i = 0; i < 67; i++) {
            data = abi.encodePacked(data, vSig.elements[i]);
        }
        return data;
    }
}
