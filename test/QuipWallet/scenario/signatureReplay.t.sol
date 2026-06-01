// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @title Signature Replay Protection Tests
/// @dev Validates that WOTS+ signatures cannot be replayed across wallets,
///      chains, operations, or after key rotation.
contract QuipWallet_signatureReplay is QuipWalletTest {
    /// @dev After rotating the key, an old signature for the previous pqOwner
    ///      must not be accepted.
    function test_signatureReplay_oldSignatureFailsAfterKeyRotation() public {
        uint256 transferAmount = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "next-key-1"
        );

        // Build a valid execute (transfer) signature with alicePrivateKey
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            transferAmount,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        // Consume alicePubkey via a benign execute that rotates it out of the
        // transaction set.
        (
            WOTSPlus.WinternitzAddress memory rotatedPubkey,
            bytes32 rotatedPrivKey
        ) = _generateKeyPair("rotated-key");
        uint256 rotateFee = wallet.getExecuteFee();
        bytes32 rotateMsgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            rotatedPubkey,
            BOB,
            0,
            "",
            rotateFee
        );
        WOTSPlus.WinternitzElements memory rotateSig = _sign(
            alicePrivateKey,
            rotateMsgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                rotatedPubkey,
                rotateSig,
                BOB,
                0,
                ""
            )
        );

        // Now try to replay the original signature — alicePubkey was consumed
        // by the rotation above, so it is no longer a member of the set.
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                transferAmount,
                ""
            )
        );
    }

    /// @dev A signature computed for wallet A must not work on wallet B,
    ///      even if both share the same initial pqOwner.
    function test_signatureReplay_crossWalletSignatureFails() public {
        // Deploy a second wallet for BOB using a DIFFERENT seed but same recovery structure
        (
            address bobWalletAddr,
            WOTSPlus.WinternitzAddress memory bobPubkey,
            bytes32 bobPrivateKey,

        ) = _createWallet(BOB, "bob-replay-vault", INITIAL_DEPOSIT);

        // Build a valid execute signature for ALICE's wallet
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "next-key-cross"
        );
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            0.1 ether,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        // Try to use Alice's signature on Bob's wallet — alicePubkey is not
        // a transaction key in Bob's wallet, so it fails at the key-set check
        // before signature verification.
        QuipWallet bobWallet = QuipWallet(payable(bobWalletAddr));
        vm.prank(BOB);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        bobWallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                0.1 ether,
                ""
            )
        );
    }

    /// @dev Two distinct in-keyset auth keys X and Y rotate independently:
    ///      one execute consumes X→X', the next consumes Y→Y', both land. Locks
    ///      down keyset independence so a future "single rotation per block",
    ///      shared-cooldown, or transient-mutex refactor cannot silently
    ///      degrade UX by serializing rotations across distinct keys.
    function test_signatureReplay_distinctAuthKeysRotateIndependently()
        public
    {
        (WOTSPlus.WinternitzAddress memory nextX, ) = _generateKeyPair(
            "indep-next-X"
        );
        (WOTSPlus.WinternitzAddress memory nextY, ) = _generateKeyPair(
            "indep-next-Y"
        );

        uint256 amountX = 0.05 ether;
        uint256 amountY = 0.07 ether;

        bytes memory payloadX = _signedTransferPayload(
            aliceTxnPubkeys[0],
            aliceTxnPrivkeys[0],
            nextX,
            amountX
        );
        bytes memory payloadY = _signedTransferPayload(
            aliceTxnPubkeys[1],
            aliceTxnPrivkeys[1],
            nextY,
            amountY
        );

        uint256 bobBalBefore = BOB.balance;

        vm.prank(ALICE);
        wallet.execute(payloadX);

        vm.prank(ALICE);
        wallet.execute(payloadY);

        // Both rotations landed: X and Y are gone, their successors present.
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[0]));
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[1]));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextX));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextY));

        // Both transfers landed.
        assertEq(BOB.balance, bobBalBefore + amountX + amountY);
    }

    /// @dev Two distinct auth keys X and Y signing payloads that share the
    ///      SAME nextKey N: the first lands and installs N; the second reverts
    ///      with `KeyInUse` because `_safeAddKey(N)` runs `_enforceUnspentKey`
    ///      against the fully-updated keyset. Locks down the cross-tx
    ///      uniqueness check so a future refactor relaxing the "no key already
    ///      present" rule (e.g. a recently-rotated grace period) cannot
    ///      silently let one WOTS+ public key live in two slots — which would
    ///      let a single revealed signature consume it twice.
    function test_signatureReplay_collidingNextKeyRevertsWithKeyInUse()
        public
    {
        // Same nextKey N for both payloads — owner-side mistake (or attacker
        // post-leak) that the wallet must catch.
        (WOTSPlus.WinternitzAddress memory nextN, ) = _generateKeyPair(
            "colliding-next-N"
        );

        bytes memory payloadX = _signedTransferPayload(
            aliceTxnPubkeys[0],
            aliceTxnPrivkeys[0],
            nextN,
            0.05 ether
        );
        bytes memory payloadY = _signedTransferPayload(
            aliceTxnPubkeys[1],
            aliceTxnPrivkeys[1],
            nextN,
            0.07 ether
        );

        // First payload lands: X rotated out, N installed.
        vm.prank(ALICE);
        wallet.execute(payloadX);
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextN));

        // Second payload reverts at `_safeAddKey(N)` → `_enforceUnspentKey` →
        // `KeyInUse`. The earlier `_safeRemoveKey(Y)` is rolled back.
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.execute(payloadY);

        // Y must still be present; the failed tx's removal was reverted.
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, aliceTxnPubkeys[1]));
    }

    /// @dev Builds a fully-signed `execute` payload that transfers `value` to
    ///      BOB and rotates `currentKey` to `nextKey`. Extracted so the
    ///      multi-signature replay tests stay stack-bounded.
    function _signedTransferPayload(
        WOTSPlus.WinternitzAddress memory currentKey,
        bytes32 currentPriv,
        WOTSPlus.WinternitzAddress memory nextKey,
        uint256 value
    ) internal view returns (bytes memory) {
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            currentKey,
            nextKey,
            BOB,
            value,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, msgHash);
        return Codec.encodeExecute(currentKey, nextKey, sig, BOB, value, "");
    }

    /// @dev A signature for a pure transfer (empty data) cannot be used for a
    ///      contract call (non-empty data), because the dataHash differs.
    function test_signatureReplay_dataHashDifferentiatesOperations() public {
        uint256 value = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "next-key-cross-op"
        );

        // Build a signature for a pure transfer (empty data)
        bytes32 transferMsgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            value,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory transferSig = _sign(
            alicePrivateKey,
            transferMsgHash
        );

        // Try using it for a call with non-empty data — different dataHash
        bytes memory callData = abi.encodeWithSignature("nonExistent()");
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                transferSig,
                BOB,
                value,
                callData
            )
        );
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*       CROSS-FUNCTION / CROSS-TAG REPLAY (resetKeyset           */
    /*       vs replaceKeys, and within each: cross-(signingKind,     */
    /*       kind) lifting). Mirrors the legacy addKeys↔refreshKeys   */
    /*       cross-mode coverage for the new function pair.           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev A `resetKeyset(Recovery, txSign, …)` signature MUST NOT verify
    ///      when lifted into a `replaceKeys(Recovery, txSign, …)` call with
    ///      otherwise-identical fields. Distinct `RESET_KEYSET_*` and
    ///      `REPLACE_KEYS_*` tag families bind each preimage to its function
    ///      family; the digests differ, so the WOTS+ verify fails.
    function test_signatureReplay_resetKeysetSigCannotBeLiftedToReplaceKeys()
        public
    {
        // 10 fresh recovery keys for resetKeyset, plus the same 10 reused as
        // the newKeys side of a replaceKeys payload that swaps the current
        // recovery batch in for the 10 fresh ones.
        WOTSPlus.WinternitzAddress[10] memory newKeys10;
        WOTSPlus.WinternitzAddress[]
            memory newKeysDyn = new WOTSPlus.WinternitzAddress[](10);
        for (uint256 i = 0; i < 10; i++) {
            (newKeys10[i], ) = _generateKeyPair(
                keccak256(abi.encode("xfn-rec-new", i))
            );
            newKeysDyn[i] = newKeys10[i];
        }
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "xfn-rec-next"
        );

        // Sign the resetKeyset digest with alicePrivateKey.
        bytes32 resetDigest = _buildResetKeysetMessageHash(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys10
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            resetDigest
        );

        // Lift that exact sig into a replaceKeys(Recovery, Transaction, n=10)
        // payload. `oldKeys` is the wallet's current recovery batch so the
        // remove side would succeed; what should fail is signature
        // verification (the wallet recomputes replaceKeysDigest, which uses
        // REPLACE_KEYS_TXSIGN_RECOVERY_TAG, not the reset tag).
        WOTSPlus.WinternitzAddress[]
            memory oldKeysDyn = new WOTSPlus.WinternitzAddress[](10);
        for (uint256 i = 0; i < 10; i++) {
            oldKeysDyn[i] = recoveryPubkeys[i];
        }
        bytes memory replacePayload = Codec.encodeReplaceKeys(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            10,
            alicePubkey,
            nextPq,
            sig,
            oldKeysDyn,
            newKeysDyn
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.replaceKeys(replacePayload);
    }

    /// @dev Mirror direction: a `replaceKeys` sig MUST NOT lift into
    ///      `resetKeyset`. Asymmetrically the more dangerous direction — a
    ///      lifted reset signature would WIPE the target keyset, whereas a
    ///      lifted replace would only attempt a same-N swap.
    function test_signatureReplay_replaceKeysSigCannotBeLiftedToResetKeyset()
        public
    {
        WOTSPlus.WinternitzAddress[10] memory newKeys10;
        WOTSPlus.WinternitzAddress[]
            memory newKeysDyn = new WOTSPlus.WinternitzAddress[](10);
        WOTSPlus.WinternitzAddress[]
            memory oldKeysDyn = new WOTSPlus.WinternitzAddress[](10);
        for (uint256 i = 0; i < 10; i++) {
            (newKeys10[i], ) = _generateKeyPair(
                keccak256(abi.encode("xfn-mirror-new", i))
            );
            newKeysDyn[i] = newKeys10[i];
            oldKeysDyn[i] = recoveryPubkeys[i];
        }
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "xfn-mirror-next"
        );

        bytes32 replaceDigest = _buildReplaceKeysMessageHash(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            address(wallet),
            alicePubkey,
            nextPq,
            oldKeysDyn,
            newKeysDyn
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            replaceDigest
        );

        bytes memory resetPayload = Codec.encodeResetKeyset(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            alicePubkey,
            nextPq,
            sig,
            newKeys10
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.resetKeyset(resetPayload);
    }

    /// @dev A `replaceKeys(Recovery, txSign, …)` signature MUST NOT lift into
    ///      `replaceKeys(Recovery, recoverySign, …)` even with identical
    ///      currentKey/nextKey/oldKeys/newKeys. The 6-tag taxonomy (signing ×
    ///      target) prevents cross-signingKind replay within the same
    ///      function. The `signingKind` field is encoded in the digest and
    ///      ALSO selects which keyset is checked for `currentKey` membership;
    ///      we sign with alicePrivateKey (tx) but the lifted call claims rec.
    function test_signatureReplay_replaceKeys_txSigCannotBeLiftedToRecoverySig()
        public
    {
        WOTSPlus.WinternitzAddress[]
            memory oldKeysDyn = new WOTSPlus.WinternitzAddress[](2);
        WOTSPlus.WinternitzAddress[]
            memory newKeysDyn = new WOTSPlus.WinternitzAddress[](2);
        oldKeysDyn[0] = recoveryPubkeys[0];
        oldKeysDyn[1] = recoveryPubkeys[1];
        (newKeysDyn[0], ) = _generateKeyPair("xsign-new-0");
        (newKeysDyn[1], ) = _generateKeyPair("xsign-new-1");
        (WOTSPlus.WinternitzAddress memory nextRec, ) = _generateKeyPair(
            "xsign-next-rec"
        );

        // Sign for (kind=Recovery, signingKind=Transaction). currentKey is
        // alicePubkey, which is in the tx set.
        bytes32 txSignDigest = _buildReplaceKeysMessageHash(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            address(wallet),
            alicePubkey,
            nextRec,
            oldKeysDyn,
            newKeysDyn
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            txSignDigest
        );

        // Lift to (kind=Recovery, signingKind=Recovery). Wallet's
        // `_verifyAndRotate` routes membership-check at `recoveryKeys`, which
        // does NOT contain alicePubkey — so `_enforceContained` reverts
        // `UnknownKey` BEFORE signature verification runs. That's the layered
        // defense the cross-signingKind tag delivers: even if a future
        // refactor regressed the digest separation, the membership routing
        // would still catch this.
        bytes memory liftedPayload = Codec.encodeReplaceKeys(
            Codec.KeyType.Recovery,
            Codec.KeyType.Recovery,
            2,
            alicePubkey,
            nextRec,
            sig,
            oldKeysDyn,
            newKeysDyn
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.replaceKeys(liftedPayload);
    }

    /// @dev A `replaceKeys(Recovery, txSign, …)` signature MUST NOT lift into
    ///      `replaceKeys(Verification, txSign, …)` — the 6-tag taxonomy also
    ///      separates targets within a fixed signingKind. Here the
    ///      currentKey (alicePubkey) IS in the tx set so membership passes;
    ///      what blocks the lift is the digest tag (recovery vs verify).
    function test_signatureReplay_replaceKeys_recoveryTargetSigCannotBeLiftedToVerifyTarget()
        public
    {
        // Seed verification so the lifted call has somewhere to remove from.
        _seedVerificationKeys(10);

        WOTSPlus.WinternitzAddress[]
            memory oldKeysDyn = new WOTSPlus.WinternitzAddress[](1);
        WOTSPlus.WinternitzAddress[]
            memory newKeysDyn = new WOTSPlus.WinternitzAddress[](1);
        oldKeysDyn[0] = recoveryPubkeys[0];
        (newKeysDyn[0], ) = _generateKeyPair("xkind-new-0");
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "xkind-next"
        );

        // Sign for (kind=Recovery, signingKind=Transaction).
        // `_seedVerificationKeys` rotated alicePubkey, so re-read.
        bytes32 recoveryDigest = _buildReplaceKeysMessageHash(
            Codec.KeyType.Recovery,
            Codec.KeyType.Transaction,
            address(wallet),
            alicePubkey,
            nextPq,
            oldKeysDyn,
            newKeysDyn
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            recoveryDigest
        );

        // Lift to (kind=Verification, signingKind=Transaction). Same auth
        // key, same n, same keys — but the digest tag is
        // REPLACE_KEYS_TXSIGN_VERIFY_TAG, not REPLACE_KEYS_TXSIGN_RECOVERY_TAG.
        bytes memory liftedPayload = Codec.encodeReplaceKeys(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            1,
            alicePubkey,
            nextPq,
            sig,
            oldKeysDyn,
            newKeysDyn
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.replaceKeys(liftedPayload);
    }

    /// @dev Audit-driven regression for the new function pair: a key
    ///      previously installed and spent CANNOT be reinstalled via
    ///      `resetKeyset`, even on a different keyset. Burns persist in the
    ///      global `isKeySpent` index, and `_safeAddKey`'s
    ///      `_enforceUnspentKey` re-checks it on every install.
    function test_signatureReplay_resetKeyset_revertsWhen_installsSpentKey()
        public
    {
        // Step 1: spend alicePubkey via execute, rotating it out.
        (
            WOTSPlus.WinternitzAddress memory rotatedPubkey,
            bytes32 rotatedPriv
        ) = _generateKeyPair("audit-reset-burn-rotated");
        uint256 rotateFee = wallet.getExecuteFee();
        bytes32 rotateMsgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            rotatedPubkey,
            BOB,
            0,
            "",
            rotateFee
        );
        WOTSPlus.WinternitzElements memory rotateSig = _sign(
            alicePrivateKey,
            rotateMsgHash
        );
        vm.prank(ALICE);
        wallet.execute{value: rotateFee}(
            Codec.encodeExecute(
                alicePubkey,
                rotatedPubkey,
                rotateSig,
                BOB,
                0,
                ""
            )
        );
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));

        // Step 2: build a resetKeyset(Verification, txSign) payload that
        // includes the spent alicePubkey in newKeys[7]. The signing
        // currentKey is the now-active rotatedPubkey.
        WOTSPlus.WinternitzAddress[10] memory newKeys10;
        for (uint256 i = 0; i < 10; i++) {
            (newKeys10[i], ) = _generateKeyPair(
                keccak256(abi.encode("audit-reset-fresh", i))
            );
        }
        newKeys10[7] = alicePubkey; // the SPENT key

        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "audit-reset-next"
        );
        bytes32 resetDigest = _buildResetKeysetMessageHash(
            Codec.KeyType.Verification,
            Codec.KeyType.Transaction,
            address(wallet),
            rotatedPubkey,
            nextPq,
            newKeys10
        );
        WOTSPlus.WinternitzElements memory resetSig = _sign(
            rotatedPriv,
            resetDigest
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.resetKeyset(
            Codec.encodeResetKeyset(
                Codec.KeyType.Verification,
                Codec.KeyType.Transaction,
                rotatedPubkey,
                nextPq,
                resetSig,
                newKeys10
            )
        );

        // The spent key was not partially installed.
        assertFalse(wallet.isKey(Codec.KeyType.Verification, alicePubkey));
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, alicePubkey));
    }
}
