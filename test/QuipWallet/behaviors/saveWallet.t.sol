// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

contract QuipWallet_saveWallet is QuipWalletTest {
    /// @dev Derived deterministically by the test base from the vault seed.
    WOTSPlus.WinternitzAddress internal disasterPub;
    bytes32 internal disasterPriv;

    /// @dev A fresh batch of 5 transaction keys for rescue testing.
    WOTSPlus.WinternitzAddress[5] internal freshTxnKeys;
    /// @dev A fresh batch of 10 recovery keys for rescue testing.
    WOTSPlus.WinternitzAddress[10] internal freshRecoveryKeys;

    function setUp() public override {
        super.setUp();
        (disasterPub, disasterPriv) = _generateDisasterRecoveryKey(VAULT_SEED);
        for (uint256 i = 0; i < 5; i++) {
            (freshTxnKeys[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked("fresh-txn", i))
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            (freshRecoveryKeys[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked("fresh-rec", i))
            );
        }
    }

    function _buildSaveWalletDigest(
        WOTSPlus.WinternitzAddress memory cur,
        WOTSPlus.WinternitzAddress memory next_
    ) internal view returns (bytes32) {
        bytes32 keysHash = keccak256(
            abi.encode(freshTxnKeys, freshRecoveryKeys)
        );
        return
            Codec.saveWalletDigest(
                address(wallet),
                block.chainid,
                cur.publicSeed,
                cur.publicKeyHash,
                next_.publicSeed,
                next_.publicKeyHash,
                keysHash
            );
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_saveWallet_replacesTxnAndRecoveryKeys() public {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "new-disaster-key"
        );
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        // Sanity: original txn/recovery keys are present.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[0]));

        // Anyone can call — saveWallet has no access gate.
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );

        // Counts unchanged, but membership replaced.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        for (uint256 i = 0; i < 5; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[i])
            );
            assertTrue(
                wallet.isKey(Codec.KeyType.Transaction, freshTxnKeys[i])
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i])
            );
            assertTrue(
                wallet.isKey(Codec.KeyType.Recovery, freshRecoveryKeys[i])
            );
        }
    }

    function test_saveWallet_preservesVerificationKeys() public {
        // Seed verification keys before rescue.
        (
            WOTSPlus.WinternitzAddress[] memory verKeys,

        ) = _seedVerificationKeys(3);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);

        // Seeding consumes the initial transaction key; derive current disaster key
        // from the unchanged vault seed. The current disaster key is still in storage.
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "preserve-ver-new-disaster"
        );
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );

        // Verification keyset is untouched.
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Verification, verKeys[i]));
        }
    }

    function test_saveWallet_rotatesDisasterKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "rotate-disaster"
        );
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );

        // Replaying with the old (now-consumed) disaster key must fail.
        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    function test_saveWallet_emitsWalletSaved() public {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "emit-disaster"
        );
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectEmit(true, true, true, true);
        emit IQuipWallet.WalletSaved(
            disasterPub,
            newDisaster,
            keccak256(abi.encode(freshTxnKeys)),
            keccak256(abi.encode(freshRecoveryKeys))
        );
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    // ── Revert paths ─────────────────────────────────────────────────

    function test_saveWallet_revertsWhen_currentDisasterKeyMismatch() public {
        (
            WOTSPlus.WinternitzAddress memory bogus,
            bytes32 bogusPriv
        ) = _generateKeyPair("bogus-current-disaster");
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "mismatch-new-disaster"
        );
        bytes32 digest = _buildSaveWalletDigest(bogus, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(bogusPriv, digest);

        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                bogus,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    function test_saveWallet_revertsWhen_newDisasterKeyEqualsCurrent() public {
        bytes32 digest = _buildSaveWalletDigest(disasterPub, disasterPub);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IQuipWallet.SameKey.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                disasterPub,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    function test_saveWallet_revertsWhen_newDisasterKeyIsZero() public {
        WOTSPlus.WinternitzAddress memory zero = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });
        bytes32 digest = _buildSaveWalletDigest(disasterPub, zero);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                zero,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    function test_saveWallet_revertsWhen_badSignature() public {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "bad-sig-new-disaster"
        );
        // Sign with the wrong private key.
        (, bytes32 wrongPriv) = _generateKeyPair("wrong-signer");
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory bad = _sign(wrongPriv, digest);

        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                bad,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    // ── Cross-set key reuse (KeyInUse) ───────────────────────────────

    /// @dev `newDisasterKey == ownershipKey`. Caught by
    ///      `_enforceUnusedKey(newDisasterKey)` BEFORE WOTS+ verify, since the
    ///      ownership slot is still populated at that point.
    function test_saveWallet_revertsWhen_newDisasterKeyEqualsOwnershipKey()
        public
    {
        bytes32 digest = _buildSaveWalletDigest(disasterPub, ownershipPubkey);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                ownershipPubkey,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    /// @dev A new transaction key collides with the just-installed
    ///      `newDisasterKey`. Caught by the txn loop's `_safeAddKey` →
    ///      `_enforceUnusedKey` → `KeyInUse`.
    function test_saveWallet_revertsWhen_newTxnKeyEqualsNewDisasterKey()
        public
    {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "txn-eq-disaster"
        );
        freshTxnKeys[2] = newDisaster;
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    /// @dev A new transaction key collides with the still-installed
    ///      ownership key (saveWallet does not touch `ownershipKey`).
    function test_saveWallet_revertsWhen_newTxnKeyEqualsOwnershipKey() public {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "txn-eq-own-d"
        );
        freshTxnKeys[1] = ownershipPubkey;
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    /// @dev A new recovery key collides with `newDisasterKey`. Caught by the
    ///      recovery loop's `_safeAddKey` after the txn loop has run cleanly.
    function test_saveWallet_revertsWhen_newRecoveryKeyEqualsNewDisasterKey()
        public
    {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "rec-eq-disaster"
        );
        freshRecoveryKeys[5] = newDisaster;
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    /// @dev A new recovery key collides with the still-installed ownership key.
    function test_saveWallet_revertsWhen_newRecoveryKeyEqualsOwnershipKey()
        public
    {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "rec-eq-own-d"
        );
        freshRecoveryKeys[3] = ownershipPubkey;
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    /// @dev Cross-input collision: a recovery-key entry equals one of the
    ///      transaction-key entries. The txn loop runs first; the recovery
    ///      loop's `_safeAddKey` sees the key already in `transactionKeys`.
    function test_saveWallet_revertsWhen_newRecoveryKeyEqualsNewTxnKey()
        public
    {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "rec-eq-txn-d"
        );
        freshRecoveryKeys[4] = freshTxnKeys[0];
        bytes32 digest = _buildSaveWalletDigest(disasterPub, newDisaster);
        WOTSPlus.WinternitzElements memory sig = _sign(disasterPriv, digest);

        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }

    /// @dev Digest must be bound to this wallet — a signature good for another wallet
    ///      must not verify.
    function test_saveWallet_isBoundToWallet() public {
        (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
            "bound-to-wallet-new-disaster"
        );
        bytes32 keysHash = keccak256(
            abi.encode(freshTxnKeys, freshRecoveryKeys)
        );
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

        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.saveWallet(
            Codec.encodeSaveWallet(
                disasterPub,
                newDisaster,
                sig,
                freshTxnKeys,
                freshRecoveryKeys
            )
        );
    }
}
