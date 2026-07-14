// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";

contract WOTSPlusImplementation_saveWallet is WOTSPlusImplementationTest {
    /// @dev Derived deterministically by the test base from the vault seed.
    WOTSPlus.WinternitzAddress internal disasterPub;
    bytes32 internal disasterPriv;

    /// @dev Fresh always-10 batches for rescue testing.
    WOTSPlus.WinternitzAddress[10] internal freshTxnKeys;
    WOTSPlus.WinternitzAddress[10] internal freshRecoveryKeys;
    WOTSPlus.WinternitzAddress[10] internal freshVerificationKeys;

    function setUp() public override {
        super.setUp();
        (disasterPub, disasterPriv) = _generateDisasterRecoveryKey(VAULT_SEED);
        for (uint256 i = 0; i < 10; i++) {
            (freshTxnKeys[i],) = _generateKeyPair(keccak256(abi.encodePacked("fresh-txn", i)));
            (freshRecoveryKeys[i],) = _generateKeyPair(keccak256(abi.encodePacked("fresh-rec", i)));
            (freshVerificationKeys[i],) = _generateKeyPair(keccak256(abi.encodePacked("fresh-ver", i)));
        }
    }

    function _buildSaveWalletDigest(WOTSPlus.WinternitzAddress memory cur, WOTSPlus.WinternitzAddress memory next_)
        internal
        view
        returns (bytes32)
    {
        bytes32 keysHash = keccak256(abi.encode(freshTxnKeys, freshRecoveryKeys, freshVerificationKeys));
        return Codec.saveWalletDigest(
            address(wallet),
            block.chainid,
            cur.publicSeed,
            cur.publicKeyHash,
            next_.publicSeed,
            next_.publicKeyHash,
            keysHash
        );
    }

    function _encodedSavePayload(
        WOTSPlus.WinternitzAddress memory cur,
        WOTSPlus.WinternitzAddress memory next_,
        WOTSPlus.WinternitzElements memory sig
    ) internal view returns (bytes memory) {
        return Codec.encodeSaveWallet(cur, next_, sig, freshTxnKeys, freshRecoveryKeys, freshVerificationKeys);
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_saveWallet_replacesAllThreeKeysets() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("new-disaster-key");
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        // Sanity: original keysets full at init.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 10);
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[0]));

        // Anyone can call — saveWallet has no access gate.
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));

        // All three keysets cleared and reinstalled at full size.
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

    function test_saveWallet_rotatesDisasterKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("rotate-disaster");
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));

        // Replaying with the old (now-consumed) disaster key must fail.
        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    function test_saveWallet_emitsWalletSaved() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("emit-disaster");
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectEmit(true, true, true, true);
        emit IWOTSPlusImplementation.WalletSaved(
            disasterPub,
            newDisaster,
            keccak256(abi.encode(freshTxnKeys)),
            keccak256(abi.encode(freshRecoveryKeys)),
            keccak256(abi.encode(freshVerificationKeys))
        );
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    // ── Revert paths ─────────────────────────────────────────────────

    function test_saveWallet_revertsWhen_currentDisasterKeyMismatch() public {
        (WOTSPlus.WinternitzAddress memory bogus, bytes32 bogusPriv) = _generateKeyPair("bogus-current-disaster");
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("mismatch-new-disaster");
        bytes32 digest = _buildSaveWalletDigest(bogus, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(bogusPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        wallet.saveWallet(_encodedSavePayload(bogus, newDisaster, sig));
    }

    function test_saveWallet_revertsWhen_newDisasterKeyEqualsCurrent() public {
        bytes32 digest = _buildSaveWalletDigest(disasterPub, disasterPub);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, disasterPub, sig));
    }

    function test_saveWallet_revertsWhen_newDisasterKeyIsZero() public {
        WOTSPlus.WinternitzAddress memory zero =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        bytes32 digest = _buildSaveWalletDigest(disasterPub, zero);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.UnknownDisasterRecoveryKey.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, zero, sig));
    }

    function test_saveWallet_revertsWhen_badSignature() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("bad-sig-new-disaster");
        // Sign with the wrong private key.
        (, bytes32 wrongPriv) = _generateKeyPair("wrong-signer");
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory bad = _sign(wrongPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, bad));
    }

    // ── Cross-set key reuse (KeyInUse) ───────────────────────────────

    /// @dev `newDisasterKey == ownershipKey`. Caught by
    ///      `_enforceUnspentKey(newDisasterKey)` BEFORE WOTS+ verify, since the
    ///      ownership slot is still populated at that point.
    function test_saveWallet_revertsWhen_newDisasterKeyEqualsOwnershipKey() public {
        bytes32 digest = _buildSaveWalletDigest(disasterPub, ownershipPubkey);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, ownershipPubkey, sig));
    }

    /// @dev A new transaction key collides with the just-installed
    ///      `newDisasterKey`. Caught by the txn loop's `_safeAddKey` →
    ///      `_enforceUnspentKey` → `KeyInUse`.
    function test_saveWallet_revertsWhen_newTxnKeyEqualsNewDisasterKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("txn-eq-disaster");
        freshTxnKeys[2] = newDisaster;
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    /// @dev A new transaction key collides with the still-installed
    ///      ownership key (saveWallet does not touch `ownershipKey`).
    function test_saveWallet_revertsWhen_newTxnKeyEqualsOwnershipKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("txn-eq-own-d");
        freshTxnKeys[1] = ownershipPubkey;
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    /// @dev A new recovery key collides with `newDisasterKey`. Caught by the
    ///      recovery loop's `_safeAddKey` after the txn loop has run cleanly.
    function test_saveWallet_revertsWhen_newRecoveryKeyEqualsNewDisasterKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("rec-eq-disaster");
        freshRecoveryKeys[5] = newDisaster;
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    /// @dev A new recovery key collides with the still-installed ownership key.
    function test_saveWallet_revertsWhen_newRecoveryKeyEqualsOwnershipKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("rec-eq-own-d");
        freshRecoveryKeys[3] = ownershipPubkey;
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    /// @dev Cross-input collision: a recovery-key entry equals one of the
    ///      transaction-key entries. The txn loop runs first; the recovery
    ///      loop's `_safeAddKey` sees the key already in `transactionKeys`.
    function test_saveWallet_revertsWhen_newRecoveryKeyEqualsNewTxnKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("rec-eq-txn-d");
        freshRecoveryKeys[4] = freshTxnKeys[0];
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    /// @dev A new verification key collides with `newDisasterKey`. Caught by
    ///      the verification loop's `_safeAddKey` after txn + recovery run
    ///      cleanly.
    function test_saveWallet_revertsWhen_newVerificationKeyEqualsNewDisasterKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("ver-eq-disaster");
        freshVerificationKeys[6] = newDisaster;
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    /// @dev A new verification key collides with a new transaction key.
    function test_saveWallet_revertsWhen_newVerificationKeyEqualsNewTxnKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("ver-eq-txn-d");
        freshVerificationKeys[2] = freshTxnKeys[0];
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    /// @dev A new verification key collides with a new recovery key.
    function test_saveWallet_revertsWhen_newVerificationKeyEqualsNewRecoveryKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("ver-eq-rec-d");
        freshVerificationKeys[7] = freshRecoveryKeys[0];
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }

    /// @dev Digest must be bound to this wallet — a signature good for another wallet
    ///      must not verify.
    function test_saveWallet_isBoundToWallet() public {
        (WOTSPlus.WinternitzAddress memory newDisaster,) = _generateKeyPair("bound-to-wallet-new-disaster");
        bytes32 keysHash = keccak256(abi.encode(freshTxnKeys, freshRecoveryKeys, freshVerificationKeys));
        // Sign a digest bound to a DIFFERENT wallet address.
        bytes32 digest = Codec.saveWalletDigest(
            address(0xdeadbeef),
            block.chainid,
            disasterPub.publicSeed,
            disasterPub.publicKeyHash,
            newDisaster.publicSeed,
            newDisaster.publicKeyHash,
            keysHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.saveWallet(_encodedSavePayload(disasterPub, newDisaster, sig));
    }
}
