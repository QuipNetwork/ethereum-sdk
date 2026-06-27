// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";

contract WOTSPlusImplementation_transferOwnership is WOTSPlusImplementationTest {
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    WOTSPlus.WinternitzAddress internal newOwnershipKey;
    WOTSPlus.WinternitzAddress internal newDisasterKey;
    WOTSPlus.WinternitzAddress[10] internal freshTxnKeys;
    WOTSPlus.WinternitzAddress[10] internal freshRecoveryKeys;
    WOTSPlus.WinternitzAddress[10] internal freshVerificationKeys;

    function setUp() public override {
        super.setUp();
        (newOwnershipKey,) = _generateKeyPair("xfer-owner-new-ownership");
        (newDisasterKey,) = _generateKeyPair("xfer-owner-new-disaster");
        for (uint256 i = 0; i < 10; i++) {
            (freshTxnKeys[i],) = _generateKeyPair(keccak256(abi.encodePacked("xfer-txn", i)));
        }
        for (uint256 i = 0; i < 10; i++) {
            (freshRecoveryKeys[i],) = _generateKeyPair(keccak256(abi.encodePacked("xfer-rec", i)));
        }
        for (uint256 i = 0; i < 10; i++) {
            (freshVerificationKeys[i],) = _generateKeyPair(keccak256(abi.encodePacked("xfer-ver", i)));
        }
    }

    function _keysHash() internal view returns (bytes32) {
        return keccak256(abi.encode(newDisasterKey, freshTxnKeys, freshRecoveryKeys, freshVerificationKeys));
    }

    function _buildPayload(
        WOTSPlus.WinternitzAddress memory curOwnership,
        bytes32 curOwnershipPriv,
        WOTSPlus.WinternitzAddress memory nextOwnership,
        address newOwner,
        WOTSPlus.WinternitzAddress memory disasterKey
    ) internal view returns (bytes memory) {
        bytes32 keysHash = keccak256(abi.encode(disasterKey, freshTxnKeys, freshRecoveryKeys, freshVerificationKeys));
        bytes32 msgHash =
            _buildTransferOwnershipMessageHash(address(wallet), curOwnership, nextOwnership, newOwner, keysHash);
        WOTSPlus.WinternitzElements memory sig = _sign(curOwnershipPriv, msgHash);
        return Codec.encodeOwnershipTransfer(
            curOwnership,
            nextOwnership,
            sig,
            newOwner,
            disasterKey,
            freshTxnKeys,
            freshRecoveryKeys,
            freshVerificationKeys
        );
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_transferOwnership_transfersOwnership() public {
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        assertEq(wallet.owner(), BOB);
    }

    /// @dev The wallet's `transferOwnership(bytes)` tail calls back into the
    ///      factory's `updateWalletOwner`, which moves the vaultId from
    ///      ALICE's set to BOB's set. This is the load-bearing assertion for
    ///      the registry-vs-owner consistency invariant.
    function test_transferOwnership_updatesFactoryRegistry() public {
        bytes32 vaultId = factory.vaultIdOf(address(wallet));
        assertNotEq(factory.getVaultIdIndex(ALICE, vaultId), type(uint256).max);
        assertEq(factory.getVaultIdIndex(BOB, vaultId), type(uint256).max);
        uint256 aliceBefore = factory.getVaultIdCount(ALICE);

        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);
        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        assertEq(factory.getVaultIdIndex(ALICE, vaultId), type(uint256).max);
        assertNotEq(factory.getVaultIdIndex(BOB, vaultId), type(uint256).max);
        assertEq(factory.getVaultIdCount(ALICE), aliceBefore - 1);
        assertEq(factory.getVaultIdCount(BOB), 1);
        // wallets[vaultId] / vaultIdOf[wallet] are immutable — only the
        // per-owner set rotates.
        assertEq(factory.wallets(vaultId), address(wallet));
        assertEq(factory.vaultIdOf(address(wallet)), vaultId);
    }

    function test_transferOwnership_replacesAllThreeKeysets() public {
        // Sanity: original keysets installed in setUp (init populates 10 of each).
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[0]));

        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[i]));
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, freshTxnKeys[i]));
            assertFalse(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i]));
            assertTrue(wallet.isKey(Codec.KeyType.Recovery, freshRecoveryKeys[i]));
            assertTrue(wallet.isKey(Codec.KeyType.Verification, freshVerificationKeys[i]));
        }
    }

    function test_transferOwnership_rotatesOwnershipKey() public {
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        // Replaying the old payload with the consumed ownership key must fail
        // — the new owner is signer now, so both the auth gate and the stored
        // ownership key would reject another call with the same material.
        vm.prank(BOB);
        vm.expectRevert(IWOTSPlusImplementation.UnknownOwnershipKey.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_rotatesDisasterKey() public {
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);
        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        // The original disaster key is gone; attempting to saveWallet with it fails.
        // Cheap proxy check: invoke saveWallet with a bogus payload and verify it
        // reverts with UnknownDisasterRecoveryKey for the old key.
        (WOTSPlus.WinternitzAddress memory origDisaster,) = _generateDisasterRecoveryKey(VAULT_SEED);
        (WOTSPlus.WinternitzAddress memory dummyNew,) = _generateKeyPair("dummy-new");
        WOTSPlus.WinternitzElements memory dummySig;
        WOTSPlus.WinternitzAddress[10] memory dummyTxn;
        WOTSPlus.WinternitzAddress[10] memory dummyRec;
        WOTSPlus.WinternitzAddress[10] memory dummyVer;
        for (uint256 i = 0; i < 10; i++) {
            (dummyTxn[i],) = _generateKeyPair(keccak256(abi.encodePacked("rotate-disaster-tx", i)));
            (dummyRec[i],) = _generateKeyPair(keccak256(abi.encodePacked("rotate-disaster-rec", i)));
            (dummyVer[i],) = _generateKeyPair(keccak256(abi.encodePacked("rotate-disaster-ver", i)));
        }
        bytes memory savePayload =
            Codec.encodeSaveWallet(origDisaster, dummyNew, dummySig, dummyTxn, dummyRec, dummyVer);
        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        wallet.saveWallet(savePayload);
    }

    function test_transferOwnership_emitsOwnershipTransferred() public {
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit OwnershipTransferred(ALICE, BOB);

        vm.prank(ALICE);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_emitsOwnershipReinitialized() public {
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.expectEmit(false, false, false, true, address(wallet));
        emit IWOTSPlusImplementation.OwnershipReinitialized(
            ownershipPubkey,
            newOwnershipKey,
            BOB,
            newDisasterKey,
            keccak256(abi.encode(freshTxnKeys)),
            keccak256(abi.encode(freshRecoveryKeys)),
            keccak256(abi.encode(freshVerificationKeys))
        );

        vm.prank(ALICE);
        wallet.transferOwnership(payload);
    }

    // ── Revert paths ─────────────────────────────────────────────────

    function test_transferOwnership_revertsWhen_classicalCalled() public {
        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.ClassicalTransferOwnershipDisabled.selector);
        wallet.transferOwnership(BOB);
    }

    function test_transferOwnership_revertsWhen_classicalCalledByNonOwner() public {
        vm.prank(BOB);
        vm.expectRevert(IWOTSPlusImplementation.ClassicalTransferOwnershipDisabled.selector);
        wallet.transferOwnership(BOB);
    }

    function test_transferOwnership_revertsWhen_callerNotOwner() public {
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_newOwnerIsZero() public {
        bytes memory payload =
            _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, address(0), newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.ZeroAddressOwner.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_currentOwnershipKeyMismatch() public {
        (WOTSPlus.WinternitzAddress memory bogus, bytes32 bogusPriv) = _generateKeyPair("bogus-current-ownership");
        bytes memory payload = _buildPayload(bogus, bogusPriv, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownOwnershipKey.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_newOwnershipKeyEqualsCurrent() public {
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, ownershipPubkey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_newOwnershipKeyIsZero() public {
        WOTSPlus.WinternitzAddress memory zero;
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, zero, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownOwnershipKey.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_newDisasterKeyIsZero() public {
        WOTSPlus.WinternitzAddress memory zero;
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, zero);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        wallet.transferOwnership(payload);
    }

    // ── Cross-set key reuse (KeyInUse / SameKey) ─────────────────────

    /// @dev `newOwnershipKey == newDisasterKey`: caught by the second
    ///      `_enforceDifferentKeys(newOwnershipKey, newDisasterKey)` pre-WOTS+
    ///      verify check → `SameKey`.
    function test_transferOwnership_revertsWhen_newOwnershipEqualsNewDisaster() public {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newOwnershipKey // newDisasterKey == newOwnershipKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev `newOwnershipKey` collides with an active transaction key
    ///      (still in storage at the `_enforceUnspentKey(newOwnershipKey)`
    ///      check, before the txn keyset is cleared) → `KeyInUse`.
    function test_transferOwnership_revertsWhen_newOwnershipKeyInTxnSet() public {
        bytes memory payload =
            _buildPayload(ownershipPubkey, ownershipPrivateKey, aliceTxnPubkeys[2], BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev `newDisasterKey` collides with the recovery keyset (still in
    ///      storage when `_enforceUnspentKey(newDisasterKey)` runs).
    function test_transferOwnership_revertsWhen_newDisasterKeyInRecoverySet() public {
        bytes memory payload =
            _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, recoveryPubkeys[1]);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev `newTxnKey == newOwnershipKey`. The ownership key is set before
    ///      the keyset loops, so the txn loop's `_safeAddKey` sees the
    ///      collision.
    function test_transferOwnership_revertsWhen_newTxnKeyEqualsNewOwnershipKey() public {
        freshTxnKeys[3] = newOwnershipKey;
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev `newTxnKey == newDisasterKey`. Disaster is set after ownership,
    ///      both before the loops, so the txn loop catches it.
    function test_transferOwnership_revertsWhen_newTxnKeyEqualsNewDisasterKey() public {
        freshTxnKeys[1] = newDisasterKey;
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev `newRecoveryKey == newDisasterKey`. Caught by the recovery loop
    ///      after the txn loop runs cleanly.
    function test_transferOwnership_revertsWhen_newRecKeyEqualsNewDisasterKey() public {
        freshRecoveryKeys[6] = newDisasterKey;
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev `newRecoveryKey == newOwnershipKey`. Caught by the recovery loop.
    function test_transferOwnership_revertsWhen_newRecKeyEqualsNewOwnershipKey() public {
        freshRecoveryKeys[2] = newOwnershipKey;
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev Cross-input: a recovery-key entry equals a transaction-key entry.
    ///      The txn loop installs first; the recovery loop catches the
    ///      collision against `transactionKeys`.
    function test_transferOwnership_revertsWhen_newRecKeyEqualsNewTxnKey() public {
        freshRecoveryKeys[7] = freshTxnKeys[0];
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev `newVerificationKey == newDisasterKey`. Caught by the verification
    ///      loop's `_safeAddKey` after the txn + recovery loops install cleanly.
    function test_transferOwnership_revertsWhen_newVerKeyEqualsNewDisasterKey() public {
        freshVerificationKeys[4] = newDisasterKey;
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev `newVerificationKey == newTxnKey`. Verification loop catches the
    ///      collision against the freshly-installed `transactionKeys` set.
    function test_transferOwnership_revertsWhen_newVerKeyEqualsNewTxnKey() public {
        freshVerificationKeys[2] = freshTxnKeys[5];
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev `newVerificationKey == newRecoveryKey`. Verification loop catches
    ///      the collision against the freshly-installed `recoveryKeys` set.
    function test_transferOwnership_revertsWhen_newVerKeyEqualsNewRecoveryKey() public {
        freshVerificationKeys[8] = freshRecoveryKeys[3];
        bytes memory payload = _buildPayload(ownershipPubkey, ownershipPrivateKey, newOwnershipKey, BOB, newDisasterKey);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_invalidSignature() public {
        bytes32 keysHash = _keysHash();
        bytes32 msgHash =
            _buildTransferOwnershipMessageHash(address(wallet), ownershipPubkey, newOwnershipKey, BOB, keysHash);
        // Sign with a key that is not the current ownership key.
        (, bytes32 wrongPriv) = _generateKeyPair("xfer-wrong-signer");
        WOTSPlus.WinternitzElements memory bad = _sign(wrongPriv, msgHash);

        bytes memory payload = Codec.encodeOwnershipTransfer(
            ownershipPubkey,
            newOwnershipKey,
            bad,
            BOB,
            newDisasterKey,
            freshTxnKeys,
            freshRecoveryKeys,
            freshVerificationKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev Digest binds the wallet address — a sig authorizing one wallet must not verify
    ///      on a different wallet even if caller and keysets match.
    function test_transferOwnership_isBoundToWallet() public {
        bytes32 keysHash = _keysHash();
        // Sign a digest bound to a DIFFERENT wallet address.
        bytes32 msgHash = Codec.transferOwnershipDigest(
            address(0xdeadbeef),
            block.chainid,
            ownershipPubkey.publicSeed,
            ownershipPubkey.publicKeyHash,
            newOwnershipKey.publicSeed,
            newOwnershipKey.publicKeyHash,
            BOB,
            keysHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(ownershipPrivateKey, msgHash);
        bytes memory payload = Codec.encodeOwnershipTransfer(
            ownershipPubkey,
            newOwnershipKey,
            sig,
            BOB,
            newDisasterKey,
            freshTxnKeys,
            freshRecoveryKeys,
            freshVerificationKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.transferOwnership(payload);
    }
}
