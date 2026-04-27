// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

/// @dev Behaviour tests for `recoverWallet(bytes)`.
///
///      `recoverWallet` performs an atomic three-key change:
///        1. `recoveryKey` is rotated out of `recoveryKeys` and replaced by
///           `newRecoveryKey` (size-preserving).
///        2. The transaction keyset is fully cleared.
///        3. `newTransactionKey` is installed as the sole transaction key.
///
///      The signed digest binds `(recoveryKey, newRecoveryKey,
///      newTransactionKey)` under the `RECOVER_WALLET_TAG` domain so a
///      signature for any other flow does not validate here.
contract QuipWallet_recoverWallet is QuipWalletTest {
    /// @dev Bundle of inputs for a `recoverWallet` call. Tests build a canonical
    ///      valid call via `_buildStandardRecoverCall` then optionally tweak a
    ///      single field (and re-sign) for negative-path tests.
    struct RecoverCall {
        WOTSPlus.WinternitzAddress recoveryKey;
        bytes32 recoveryKeyPriv;
        WOTSPlus.WinternitzAddress newRk;
        bytes32 newRkPriv;
        WOTSPlus.WinternitzAddress newPq;
        bytes32 newPqPriv;
        WOTSPlus.WinternitzElements sig;
    }

    /// @dev Builds a fully-signed recoverWallet call using
    ///      `recoveryPubkeys[keyIndex]` as the consumed recovery key.
    ///      Derives `newRk` and `newPq` deterministically from `seed`.
    function _buildRecoverCallAt(
        uint256 keyIndex,
        bytes32 seed
    ) internal view returns (RecoverCall memory call) {
        call.recoveryKey = recoveryPubkeys[keyIndex];
        call.recoveryKeyPriv = _recoverySigningKey(alicePrivateKey, keyIndex);

        (call.newRk, call.newRkPriv) = _generateKeyPair(
            keccak256(abi.encodePacked(seed, "rk"))
        );
        (call.newPq, call.newPqPriv) = _generateKeyPair(
            keccak256(abi.encodePacked(seed, "pq"))
        );

        bytes32 digest = _buildRecoverWalletMessageHash(
            address(wallet),
            call.recoveryKey,
            call.newRk,
            call.newPq
        );
        call.sig = _sign(call.recoveryKeyPriv, digest);
    }

    function _buildStandardRecoverCall(
        bytes32 seed
    ) internal view returns (RecoverCall memory) {
        return _buildRecoverCallAt(0, seed);
    }

    /// @dev Re-sign `call.sig` against the canonical digest derived from
    ///      `call`'s current `(recoveryKey, newRk, newPq)`. Used when a test
    ///      tweaks one of those fields and needs to keep the signature valid
    ///      against the tweak (so reverts originate from the tweaked field's
    ///      side-effect, not from a stale signature).
    function _resignCall(RecoverCall memory call) internal view {
        bytes32 digest = _buildRecoverWalletMessageHash(
            address(wallet),
            call.recoveryKey,
            call.newRk,
            call.newPq
        );
        call.sig = _sign(call.recoveryKeyPriv, digest);
    }

    function _encodeRecoverCall(
        RecoverCall memory call
    ) internal pure returns (bytes memory) {
        return
            Codec.encodeRecoverWallet(
                call.recoveryKey,
                call.newRk,
                call.newPq,
                call.sig
            );
    }

    function _executeRecoverCallAsOwner(RecoverCall memory call) internal {
        vm.prank(ALICE);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       STATE CHANGES                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_recoverWallet_burnsConsumedRecoveryKey() public {
        RecoverCall memory call = _buildStandardRecoverCall("burn-consumed");
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, call.recoveryKey));

        _executeRecoverCallAsOwner(call);

        assertFalse(wallet.isKey(Codec.KeyType.Recovery, call.recoveryKey));
    }

    function test_recoverWallet_installsNewRecoveryKey() public {
        RecoverCall memory call = _buildStandardRecoverCall("install-rk");
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, call.newRk));

        _executeRecoverCallAsOwner(call);

        assertTrue(wallet.isKey(Codec.KeyType.Recovery, call.newRk));
    }

    function test_recoverWallet_preservesRecoveryKeysetSize() public {
        RecoverCall memory call = _buildStandardRecoverCall("preserves-size");
        uint256 sizeBefore = wallet.keyCount(Codec.KeyType.Recovery);

        _executeRecoverCallAsOwner(call);

        assertEq(wallet.keyCount(Codec.KeyType.Recovery), sizeBefore);
    }

    function test_recoverWallet_clearsTransactionKeyset() public {
        RecoverCall memory call = _buildStandardRecoverCall("clears-txn");
        // Snapshot all 5 active txn keys before recovery; assert each is gone.
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(
                wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[i])
            );
        }

        _executeRecoverCallAsOwner(call);

        for (uint256 i = 0; i < 5; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[i])
            );
        }
    }

    function test_recoverWallet_installsNewTransactionKey() public {
        RecoverCall memory call = _buildStandardRecoverCall("install-pq");
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, call.newPq));

        _executeRecoverCallAsOwner(call);

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, call.newPq));
    }

    function test_recoverWallet_transactionKeysetHasExactlyOneKey() public {
        RecoverCall memory call = _buildStandardRecoverCall("txn-count");

        _executeRecoverCallAsOwner(call);

        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 1);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          EVENTS                                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_recoverWallet_emitsPqRecoveryWithAllThreeKeys() public {
        RecoverCall memory call = _buildStandardRecoverCall("emit-pq-recovery");

        vm.expectEmit(true, true, true, true, address(wallet));
        emit IQuipWallet.PqRecovery(call.recoveryKey, call.newRk, call.newPq);
        _executeRecoverCallAsOwner(call);
    }

    function test_recoverWallet_emitsKeyRotatedForRecoveryKey() public {
        RecoverCall memory call = _buildStandardRecoverCall("emit-rotated");

        vm.expectEmit(true, true, true, true, address(wallet));
        emit IQuipWallet.KeyRotated(call.recoveryKey, call.newRk);
        _executeRecoverCallAsOwner(call);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  POST-RECOVERY OPERATIONS                      */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_recoverWallet_newTransactionKeyCanExecute() public {
        RecoverCall memory call = _buildStandardRecoverCall("post-execute");
        _executeRecoverCallAsOwner(call);

        // Spend from the wallet using the freshly-installed transaction key.
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "post-execute-next"
        );
        uint256 fee = wallet.getExecuteFee();
        bytes32 execHash = _buildExecuteMessageHash(
            address(wallet),
            call.newPq,
            nextPq,
            BOB,
            0.05 ether,
            "",
            fee
        );
        WOTSPlus.WinternitzElements memory execSig = _sign(
            call.newPqPriv,
            execHash
        );

        uint256 bobBalBefore = BOB.balance;
        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                call.newPq,
                nextPq,
                execSig,
                BOB,
                0.05 ether,
                ""
            )
        );
        assertEq(BOB.balance, bobBalBefore + 0.05 ether);
    }

    function test_recoverWallet_replacementRecoveryKeyCanRecoverAgain() public {
        // First recovery installs `newRk` into the recovery set.
        RecoverCall memory first = _buildStandardRecoverCall("again-1");
        _executeRecoverCallAsOwner(first);
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, first.newRk));

        // Build a second recovery whose consumed key IS that replacement.
        (
            WOTSPlus.WinternitzAddress memory secondNewRk,

        ) = _generateKeyPair("again-2-rk");
        (
            WOTSPlus.WinternitzAddress memory secondNewPq,

        ) = _generateKeyPair("again-2-pq");

        bytes32 digest = _buildRecoverWalletMessageHash(
            address(wallet),
            first.newRk,
            secondNewRk,
            secondNewPq
        );
        WOTSPlus.WinternitzElements memory sig = _sign(first.newRkPriv, digest);

        vm.prank(ALICE);
        wallet.recoverWallet(
            Codec.encodeRecoverWallet(
                first.newRk,
                secondNewRk,
                secondNewPq,
                sig
            )
        );

        assertFalse(wallet.isKey(Codec.KeyType.Recovery, first.newRk));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, secondNewRk));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, secondNewPq));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                MULTI-RECOVERY SEQUENCE                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_recoverWallet_consecutiveRecoveriesPreserveCapacity() public {
        // Burn all 10 originals across 10 successive recoveries. After each
        // call, recoveryKeys.length must remain 10 (size-preserving rotation).
        for (uint256 i = 0; i < 10; i++) {
            RecoverCall memory call = _buildRecoverCallAt(i, bytes32(i));
            _executeRecoverCallAsOwner(call);
            assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        }

        // None of the original 10 recovery keys are still active.
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(
                wallet.isKey(Codec.KeyType.Recovery, recoveryPubkeys[i])
            );
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*               DOMAIN / REPLAY SEPARATION                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_recoverWallet_revertsWhen_signatureBoundToDifferentChainId()
        public
    {
        RecoverCall memory call = _buildStandardRecoverCall("wrong-chain");

        // Re-sign the WOTS+ commitment over a digest built with the wrong chainId.
        bytes32 wrongDigest = Codec.recoverWalletDigest(
            address(wallet),
            block.chainid + 1,
            call.recoveryKey.publicSeed,
            call.recoveryKey.publicKeyHash,
            call.newRk.publicSeed,
            call.newRk.publicKeyHash,
            call.newPq.publicSeed,
            call.newPq.publicKeyHash
        );
        call.sig = _sign(call.recoveryKeyPriv, wrongDigest);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_signatureBoundToDifferentWallet()
        public
    {
        RecoverCall memory call = _buildStandardRecoverCall("wrong-wallet");

        // Re-sign using a digest bound to a different wallet address.
        bytes32 wrongDigest = Codec.recoverWalletDigest(
            address(0xDEADBEEF),
            block.chainid,
            call.recoveryKey.publicSeed,
            call.recoveryKey.publicKeyHash,
            call.newRk.publicSeed,
            call.newRk.publicKeyHash,
            call.newPq.publicSeed,
            call.newPq.publicKeyHash
        );
        call.sig = _sign(call.recoveryKeyPriv, wrongDigest);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_signatureUsesKeyRotationTag()
        public
    {
        RecoverCall memory call = _buildStandardRecoverCall("wrong-tag");

        // Re-sign over `keyRotationDigest` (the tag used by changeTransactionKey)
        // instead of `recoverWalletDigest`. Distinct domain tags make the two
        // digests collision-free even on the same key tuple.
        bytes32 wrongTagDigest = Codec.keyRotationDigest(
            address(wallet),
            block.chainid,
            call.recoveryKey.publicSeed,
            call.recoveryKey.publicKeyHash,
            call.newRk.publicSeed,
            call.newRk.publicKeyHash
        );
        call.sig = _sign(call.recoveryKeyPriv, wrongTagDigest);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  SIGNATURE INTEGRITY                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_recoverWallet_revertsWhen_invalidSignature() public {
        RecoverCall memory call = _buildStandardRecoverCall("invalid-sig");

        // Sign over a totally unrelated message — produces a valid WOTS+ sig
        // but for the wrong digest.
        call.sig = _sign(call.recoveryKeyPriv, keccak256("not the digest"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_signatureBindsDifferentNewRecoveryKey()
        public
    {
        RecoverCall memory call = _buildStandardRecoverCall("sig-other-rk");

        // A different newRk that's not in the active recovery set so the
        // pre-checks all pass and we reach signature verification.
        (
            WOTSPlus.WinternitzAddress memory differentRk,

        ) = _generateKeyPair("decoy-rk");

        // Sign a digest binding `differentRk`, but submit the payload with the
        // original `call.newRk`. Contract recomputes its digest with the
        // submitted `newRk`, so the signature does not validate.
        bytes32 sigDigest = _buildRecoverWalletMessageHash(
            address(wallet),
            call.recoveryKey,
            differentRk,
            call.newPq
        );
        call.sig = _sign(call.recoveryKeyPriv, sigDigest);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_signatureBindsDifferentNewTransactionKey()
        public
    {
        RecoverCall memory call = _buildStandardRecoverCall("sig-other-pq");

        (
            WOTSPlus.WinternitzAddress memory differentPq,

        ) = _generateKeyPair("decoy-pq");

        bytes32 sigDigest = _buildRecoverWalletMessageHash(
            address(wallet),
            call.recoveryKey,
            call.newRk,
            differentPq
        );
        call.sig = _sign(call.recoveryKeyPriv, sigDigest);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                PRE-CHECK MEMBERSHIP REVERTS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_recoverWallet_revertsWhen_recoveryKeyNotInRecoverySet()
        public
    {
        RecoverCall memory call = _buildStandardRecoverCall("not-in-set");

        // Replace recoveryKey with a freshly-generated key that was never installed.
        (
            WOTSPlus.WinternitzAddress memory orphan,
            bytes32 orphanPriv
        ) = _generateKeyPair("orphan-rec");
        call.recoveryKey = orphan;
        call.recoveryKeyPriv = orphanPriv;
        _resignCall(call);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_recoveryKeyAlreadyBurned() public {
        RecoverCall memory first = _buildStandardRecoverCall("burned-1");
        _executeRecoverCallAsOwner(first);

        // Try a second recovery using the SAME recovery key. The key has
        // been rotated out of the set, so the pre-check fires UnknownKey.
        RecoverCall memory second = _buildStandardRecoverCall("burned-2");
        // Force second.recoveryKey back to first's burned key (with its priv).
        second.recoveryKey = first.recoveryKey;
        second.recoveryKeyPriv = first.recoveryKeyPriv;
        _resignCall(second);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.recoverWallet(_encodeRecoverCall(second));
    }

    function test_recoverWallet_revertsWhen_newRecoveryKeyAlreadyInRecoverySet()
        public
    {
        RecoverCall memory call = _buildStandardRecoverCall("collide-rk");

        // Use a *different* active recovery key as newRk → DuplicateKey.
        call.newRk = recoveryPubkeys[1];
        _resignCall(call);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_newRecoveryKeyEqualsBurnedRecoveryKey()
        public
    {
        RecoverCall memory call = _buildStandardRecoverCall("self-collide-rk");

        // newRk == recoveryKey: re-installing the very key being burned would
        // leave a spent WOTS+ key live in the active set. The pre-check
        // (`_enforceUncontained` against the still-populated recovery set)
        // fires DuplicateKey before any rotation runs.
        call.newRk = call.recoveryKey;
        _resignCall(call);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_newTransactionKeyAlreadyInTransactionSet()
        public
    {
        RecoverCall memory call = _buildStandardRecoverCall("collide-pq");

        // alicePubkey is an active transaction key.
        call.newPq = alicePubkey;
        _resignCall(call);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ZERO-KEY REVERTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_recoverWallet_revertsWhen_newRecoveryKeySeedZero() public {
        RecoverCall memory call = _buildStandardRecoverCall("zero-seed-rk");
        call.newRk = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(uint256(1))
        });
        _resignCall(call);

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_newRecoveryKeyHashZero() public {
        RecoverCall memory call = _buildStandardRecoverCall("zero-hash-rk");
        call.newRk = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(0)
        });
        _resignCall(call);

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_newTransactionKeySeedZero() public {
        RecoverCall memory call = _buildStandardRecoverCall("zero-seed-pq");
        call.newPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(uint256(1))
        });
        _resignCall(call);

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    function test_recoverWallet_revertsWhen_newTransactionKeyHashZero() public {
        RecoverCall memory call = _buildStandardRecoverCall("zero-hash-pq");
        call.newPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(uint256(1)),
            publicKeyHash: bytes32(0)
        });
        _resignCall(call);

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    ACCESS CONTROL                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_recoverWallet_revertsWhen_callerNotOwner() public {
        RecoverCall memory call = _buildStandardRecoverCall("not-owner");

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.recoverWallet(_encodeRecoverCall(call));
    }
}
