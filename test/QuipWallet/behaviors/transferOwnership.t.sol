// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_transferOwnership is QuipWalletTest {
    event OwnershipTransferred(
        address indexed oldOwner,
        address indexed newOwner
    );

    WOTSPlus.WinternitzAddress internal newOwnershipKey;
    WOTSPlus.WinternitzAddress internal newDisasterKey;
    WOTSPlus.WinternitzAddress[5] internal freshTxnKeys;
    WOTSPlus.WinternitzAddress[10] internal freshRecoveryKeys;

    function setUp() public override {
        super.setUp();
        (newOwnershipKey, ) = _generateKeyPair("xfer-owner-new-ownership");
        (newDisasterKey, ) = _generateKeyPair("xfer-owner-new-disaster");
        for (uint256 i = 0; i < 5; i++) {
            (freshTxnKeys[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked("xfer-txn", i))
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            (freshRecoveryKeys[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked("xfer-rec", i))
            );
        }
    }

    function _keysHash() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(newDisasterKey, freshTxnKeys, freshRecoveryKeys)
            );
    }

    function _buildPayload(
        WOTSPlus.WinternitzAddress memory curOwnership,
        bytes32 curOwnershipPriv,
        WOTSPlus.WinternitzAddress memory nextOwnership,
        address newOwner,
        WOTSPlus.WinternitzAddress memory disasterKey
    ) internal view returns (bytes memory) {
        bytes32 keysHash = keccak256(
            abi.encode(disasterKey, freshTxnKeys, freshRecoveryKeys)
        );
        bytes32 msgHash = _buildTransferOwnershipMessageHash(
            address(wallet),
            curOwnership,
            nextOwnership,
            newOwner,
            keysHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            curOwnershipPriv,
            msgHash
        );
        return
            Codec.encodeOwnershipTransfer(
                curOwnership,
                nextOwnership,
                sig,
                newOwner,
                disasterKey,
                freshTxnKeys,
                freshRecoveryKeys
            );
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_transferOwnership_transfersOwnership() public {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        assertEq(wallet.owner(), BOB);
    }

    function test_transferOwnership_replacesTxnAndRecoveryKeys() public {
        // Sanity: original keysets installed in setUp.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[0]));

        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        wallet.transferOwnership(payload);

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

    function test_transferOwnership_clearsVerificationKeys() public {
        // Seed verification keys so we can observe the clear.
        (
            WOTSPlus.WinternitzAddress[] memory verKeys,

        ) = _seedVerificationKeys(3);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);

        // `_seedVerificationKeys` consumes txn key 0; re-read alicePubkey.
        alicePubkey = wallet.keyAt(Codec.KeyType.Transaction, 0);

        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );
        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        assertEq(wallet.keyCount(Codec.KeyType.Verification), 0);
        for (uint256 i = 0; i < verKeys.length; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Verification, verKeys[i]));
        }
    }

    function test_transferOwnership_rotatesOwnershipKey() public {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        // Replaying the old payload with the consumed ownership key must fail
        // — the new owner is signer now, so both the auth gate and the stored
        // ownership key would reject another call with the same material.
        vm.prank(BOB);
        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_rotatesDisasterKey() public {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );
        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        // The original disaster key is gone; attempting to saveWallet with it fails.
        // Cheap proxy check: invoke saveWallet with a bogus payload and verify it
        // reverts with UnknownDisasterRecoveryKey for the old key.
        (
            WOTSPlus.WinternitzAddress memory origDisaster,

        ) = _generateDisasterRecoveryKey(VAULT_SEED);
        (WOTSPlus.WinternitzAddress memory dummyNew, ) = _generateKeyPair(
            "dummy-new"
        );
        WOTSPlus.WinternitzElements memory dummySig;
        bytes memory savePayload = Codec.encodeSaveWallet(
            origDisaster,
            dummyNew,
            dummySig,
            freshTxnKeys,
            freshRecoveryKeys
        );
        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        wallet.saveWallet(savePayload);
    }

    function test_transferOwnership_emitsOwnershipTransferred() public {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.expectEmit(true, true, false, false, address(wallet));
        emit OwnershipTransferred(ALICE, BOB);

        vm.prank(ALICE);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_emitsOwnershipReinitialized() public {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.expectEmit(false, false, false, true, address(wallet));
        emit IQuipWallet.OwnershipReinitialized(
            ownershipPubkey,
            newOwnershipKey,
            BOB,
            newDisasterKey,
            keccak256(abi.encode(freshTxnKeys)),
            keccak256(abi.encode(freshRecoveryKeys))
        );

        vm.prank(ALICE);
        wallet.transferOwnership(payload);
    }

    // ── Revert paths ─────────────────────────────────────────────────

    function test_transferOwnership_revertsWhen_classicalCalled() public {
        vm.prank(ALICE);
        vm.expectRevert(
            IQuipWallet.ClassicalTransferOwnershipDisabled.selector
        );
        wallet.transferOwnership(BOB);
    }

    function test_transferOwnership_revertsWhen_classicalCalledByNonOwner()
        public
    {
        vm.prank(BOB);
        vm.expectRevert(
            IQuipWallet.ClassicalTransferOwnershipDisabled.selector
        );
        wallet.transferOwnership(BOB);
    }

    function test_transferOwnership_revertsWhen_callerNotOwner() public {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_newOwnerIsZero() public {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            address(0),
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroAddressOwner.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_currentOwnershipKeyMismatch()
        public
    {
        (
            WOTSPlus.WinternitzAddress memory bogus,
            bytes32 bogusPriv
        ) = _generateKeyPair("bogus-current-ownership");
        bytes memory payload = _buildPayload(
            bogus,
            bogusPriv,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_newOwnershipKeyEqualsCurrent()
        public
    {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            ownershipPubkey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateOwnershipKey.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_newOwnershipKeyIsZero() public {
        WOTSPlus.WinternitzAddress memory zero;
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            zero,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_newDisasterKeyIsZero() public {
        WOTSPlus.WinternitzAddress memory zero;
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            zero
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_invalidSignature() public {
        bytes32 keysHash = _keysHash();
        bytes32 msgHash = _buildTransferOwnershipMessageHash(
            address(wallet),
            ownershipPubkey,
            newOwnershipKey,
            BOB,
            keysHash
        );
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
            freshRecoveryKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
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
        WOTSPlus.WinternitzElements memory sig = _sign(
            ownershipPrivateKey,
            msgHash
        );
        bytes memory payload = Codec.encodeOwnershipTransfer(
            ownershipPubkey,
            newOwnershipKey,
            sig,
            BOB,
            newDisasterKey,
            freshTxnKeys,
            freshRecoveryKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.transferOwnership(payload);
    }

    /// @dev A signature produced for `transferOwnership` must not verify when replayed
    ///      through `completeOwnershipHandover` (different domain tag).
    function test_transferOwnership_sigDoesNotReplayToCompleteHandover()
        public
    {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.completeOwnershipHandover(payload);
    }
}
