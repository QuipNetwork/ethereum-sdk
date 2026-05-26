// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";

/// @dev Cross-keyset uniqueness assertions for the public paths that install a
///      WOTS+ public key. The wallet's three keysets (transaction / recovery /
///      verification) plus the two single PQ slots (`disasterRecoveryKey`,
///      `ownershipKey`) form a single namespace: the same public key cannot
///      appear in two slots, since revealing one signature burns the WOTS+
///      secret for every possible reuse. Each test exercises a different entry
///      point and asserts `KeyInUse` when a key is already in use elsewhere.
///
///      In-set duplicate cases (which now also surface as `KeyInUse` via the
///      global pre-check) are covered in the per-path test files; this file
///      focuses exclusively on cross-set / single-key collisions, which the
///      old `_enforceUncontained(set, key)` checks did not catch.
contract QuipWallet_crossKeysetUniqueness is QuipWalletTest {
    function _disasterKey()
        internal
        view
        returns (WOTSPlus.WinternitzAddress memory pub)
    {
        (pub, ) = _generateDisasterRecoveryKey(VAULT_SEED);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       addKeys(Verification)                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Builds an addKeys(Verification) call with `newKey` as the sole new
    ///      verification key. Returns the signed payload — the test then sets
    ///      `vm.expectRevert` immediately before the wallet call to avoid the
    ///      foundry expectRevert-consumes-next-external-call hazard.
    function _prepareAddVerification(
        WOTSPlus.WinternitzAddress memory newKey,
        bytes32 nextSeed
    )
        internal
        view
        returns (
            bytes memory payload
        )
    {
        WOTSPlus.WinternitzAddress[]
            memory keys = new WOTSPlus.WinternitzAddress[](1);
        keys[0] = newKey;
        (WOTSPlus.WinternitzAddress memory nextPq, ) = WOTSPlus.generateKeyPair(
            nextSeed
        );
        bytes32 msgHash = _buildAddVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            keys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );
        payload = Codec.encodeKeyManagement(
            Codec.KeyType.Verification,
            alicePubkey,
            nextPq,
            sig,
            keys
        );
    }

    function test_addKeys_Verification_revertsWhen_newKeyInTransactionSet()
        public
    {
        bytes memory payload = _prepareAddVerification(
            aliceTxnPubkeys[1],
            keccak256("vk-next-txn")
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.addKeys(payload);
    }

    function test_addKeys_Verification_revertsWhen_newKeyInRecoverySet()
        public
    {
        bytes memory payload = _prepareAddVerification(
            recoveryPubkeys[3],
            keccak256("vk-next-rec")
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.addKeys(payload);
    }

    function test_addKeys_Verification_revertsWhen_newKeyEqualsDisasterKey()
        public
    {
        bytes memory payload = _prepareAddVerification(
            _disasterKey(),
            keccak256("vk-next-dis")
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.addKeys(payload);
    }

    function test_addKeys_Verification_revertsWhen_newKeyEqualsOwnershipKey()
        public
    {
        bytes memory payload = _prepareAddVerification(
            ownershipPubkey,
            keccak256("vk-next-own")
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.addKeys(payload);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       replaceKeyAt(Verification)               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Seeds the wallet's verification set with one fresh key and rotates
    ///      `alicePubkey` / `alicePrivateKey` to a fresh pqOwner so a follow-up
    ///      `replaceKeyAt(Verification, 0, newKey)` is signable.
    function _seedSingleVerificationKey() internal {
        WOTSPlus.WinternitzAddress[]
            memory seed = new WOTSPlus.WinternitzAddress[](1);
        (seed[0], ) = WOTSPlus.generateKeyPair(keccak256("vk-seed-existing"));

        (
            WOTSPlus.WinternitzAddress memory nextPq,
            bytes32 nextPriv
        ) = WOTSPlus.generateKeyPair(keccak256("vk-seed-next"));
        bytes32 msgHash = _buildAddVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            seed
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );
        vm.prank(ALICE);
        wallet.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Verification,
                alicePubkey,
                nextPq,
                sig,
                seed
            )
        );
        alicePubkey = nextPq;
        alicePrivateKey = nextPriv;
    }

    function _prepareReplaceVerificationAt0(
        WOTSPlus.WinternitzAddress memory newKey,
        bytes32 nextSeed
    ) internal view returns (bytes memory payload) {
        (WOTSPlus.WinternitzAddress memory nextPq, ) = WOTSPlus.generateKeyPair(
            nextSeed
        );
        bytes32 msgHash = _buildReplaceKeyAtMessageHash(
            Codec.KeyType.Verification,
            address(wallet),
            alicePubkey,
            nextPq,
            0,
            newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );
        payload = Codec.encodeReplaceKeyAt(
            Codec.KeyType.Verification,
            alicePubkey,
            nextPq,
            sig,
            0,
            newKey
        );
    }

    function test_replaceKeyAt_Verification_revertsWhen_newKeyInTransactionSet()
        public
    {
        _seedSingleVerificationKey();
        bytes memory payload = _prepareReplaceVerificationAt0(
            aliceTxnPubkeys[2],
            keccak256("rep-next-txn")
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.replaceKeyAt(payload);
    }

    function test_replaceKeyAt_Verification_revertsWhen_newKeyInRecoverySet()
        public
    {
        _seedSingleVerificationKey();
        bytes memory payload = _prepareReplaceVerificationAt0(
            recoveryPubkeys[4],
            keccak256("rep-next-rec")
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.replaceKeyAt(payload);
    }

    function test_replaceKeyAt_Verification_revertsWhen_newKeyEqualsDisasterKey()
        public
    {
        _seedSingleVerificationKey();
        bytes memory payload = _prepareReplaceVerificationAt0(
            _disasterKey(),
            keccak256("rep-next-dis")
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.replaceKeyAt(payload);
    }

    function test_replaceKeyAt_Verification_revertsWhen_newKeyEqualsOwnershipKey()
        public
    {
        _seedSingleVerificationKey();
        bytes memory payload = _prepareReplaceVerificationAt0(
            ownershipPubkey,
            keccak256("rep-next-own")
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.replaceKeyAt(payload);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          recoverWallet                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _prepareRecoverWallet(
        WOTSPlus.WinternitzAddress memory newRk,
        WOTSPlus.WinternitzAddress memory newTxnKey
    ) internal view returns (bytes memory payload) {
        WOTSPlus.WinternitzAddress memory recoveryKey = recoveryPubkeys[0];
        bytes32 recoveryPriv = _recoverySigningKey(aliceTxnPrivkeys[0], 0);
        bytes32 msgHash = _buildRecoverWalletMessageHash(
            address(wallet),
            recoveryKey,
            newRk,
            newTxnKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(recoveryPriv, msgHash);
        payload = Codec.encodeRecoverWallet(recoveryKey, newRk, newTxnKey, sig);
    }

    function test_recoverWallet_revertsWhen_newRecoveryKeyInTransactionSet()
        public
    {
        (WOTSPlus.WinternitzAddress memory freshTxn, ) = WOTSPlus.generateKeyPair(
            keccak256("rec-fresh-txn-1")
        );
        bytes memory payload = _prepareRecoverWallet(
            aliceTxnPubkeys[2],
            freshTxn
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.recoverWallet(payload);
    }

    function test_recoverWallet_revertsWhen_newRecoveryKeyEqualsDisasterKey()
        public
    {
        (WOTSPlus.WinternitzAddress memory freshTxn, ) = WOTSPlus.generateKeyPair(
            keccak256("rec-fresh-txn-2")
        );
        bytes memory payload = _prepareRecoverWallet(_disasterKey(), freshTxn);
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.recoverWallet(payload);
    }

    function test_recoverWallet_revertsWhen_newRecoveryKeyEqualsOwnershipKey()
        public
    {
        (WOTSPlus.WinternitzAddress memory freshTxn, ) = WOTSPlus.generateKeyPair(
            keccak256("rec-fresh-txn-3")
        );
        bytes memory payload = _prepareRecoverWallet(ownershipPubkey, freshTxn);
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.recoverWallet(payload);
    }

    function test_recoverWallet_revertsWhen_newTransactionKeyInRecoverySet()
        public
    {
        (WOTSPlus.WinternitzAddress memory freshRk, ) = WOTSPlus.generateKeyPair(
            keccak256("rec-fresh-rk-1")
        );
        bytes memory payload = _prepareRecoverWallet(
            freshRk,
            recoveryPubkeys[3]
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.recoverWallet(payload);
    }

    function test_recoverWallet_revertsWhen_newTransactionKeyEqualsDisasterKey()
        public
    {
        (WOTSPlus.WinternitzAddress memory freshRk, ) = WOTSPlus.generateKeyPair(
            keccak256("rec-fresh-rk-2")
        );
        bytes memory payload = _prepareRecoverWallet(freshRk, _disasterKey());
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.recoverWallet(payload);
    }

    function test_recoverWallet_revertsWhen_newTransactionKeyEqualsOwnershipKey()
        public
    {
        (WOTSPlus.WinternitzAddress memory freshRk, ) = WOTSPlus.generateKeyPair(
            keccak256("rec-fresh-rk-3")
        );
        bytes memory payload = _prepareRecoverWallet(freshRk, ownershipPubkey);
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.recoverWallet(payload);
    }
}
