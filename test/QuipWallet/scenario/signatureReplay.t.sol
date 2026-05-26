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

    /// @dev Audit-driven regression: the monotonic burn index forbids
    ///      re-installing a key that has ever lived in any keyset, even after
    ///      it was legitimately rotated out. The auditor's attack scenario is:
    ///      (1) the owner spends transactionKey A via `execute`, rotating to B,
    ///      revealing A's WOTS+ chain material on-chain; (2) later the owner
    ///      (mistakenly or under social-engineering pressure) tries to install
    ///      A back into the transaction keyset via `addKeys`; (3) an attacker
    ///      who saw A's revealed material then replays the original payload.
    ///      The fix burns A permanently in `isKeySpent`, so step (2) reverts and
    ///      step (3) never has a foothold.
    function test_signatureReplay_revertsWhen_addingSpentKeyBack() public {
        // Step 1: spend alicePubkey by rotating it out.
        (
            WOTSPlus.WinternitzAddress memory rotatedPubkey,
            bytes32 rotatedPriv
        ) = _generateKeyPair("audit-burn-rotated");
        bytes memory rotatePayload = _signedTransferPayload(
            alicePubkey,
            alicePrivateKey,
            rotatedPubkey,
            0
        );
        vm.prank(ALICE);
        wallet.execute(rotatePayload);

        // The spent key is no longer in the transaction set...
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));

        // Step 2: owner attempts to re-install the spent key via addKeys to
        // the Verification keyset (cross-keyset reuse — the most dangerous
        // form of the attack). The transaction-key rotation that authenticates
        // addKeys uses the now-active rotated key.
        (
            WOTSPlus.WinternitzAddress memory addNext,

        ) = _generateKeyPair("audit-burn-add-next");
        WOTSPlus.WinternitzAddress[] memory readd = new WOTSPlus.WinternitzAddress[](
            1
        );
        readd[0] = alicePubkey; // the SPENT key

        bytes32 addMsgHash = _buildAddVerificationKeysMessageHash(
            address(wallet),
            rotatedPubkey,
            addNext,
            readd
        );
        WOTSPlus.WinternitzElements memory addSig = _sign(
            rotatedPriv,
            addMsgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.addKeys(
            Codec.encodeKeyManagement(
                Codec.KeyType.Verification,
                rotatedPubkey,
                addNext,
                addSig,
                readd
            )
        );

        // And just to nail it down: the spent key is still NOT in any live
        // slot, so the failed install didn't accidentally land partway.
        assertFalse(wallet.isKey(Codec.KeyType.Verification, alicePubkey));
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, alicePubkey));
    }

    /// @dev Audit-driven regression: an `addKeys` signature for the Verification
    ///      keyset MUST NOT validate when lifted onto `refreshKeys`. Before the
    ///      fix the two endpoints shared a single per-kind tag, so a malicious
    ///      frontend could swap the function selector and convert "append these
    ///      keys" into "wipe and replace with these keys" — silently destroying
    ///      the owner's existing verification keyset. Now the digest commits to
    ///      `replace ∈ {false, true}` via distinct domain tags.
    function test_signatureReplay_addVerificationCannotBeLiftedToRefresh()
        public
    {
        // Seed the verification set so the destructive nature of a successful
        // lift would be visible (cleared keys).
        _seedVerificationKeys(3);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);

        // Owner builds a payload INTENDED for addKeys(Verification, ...).
        WOTSPlus.WinternitzAddress[]
            memory newKeys = new WOTSPlus.WinternitzAddress[](2);
        (newKeys[0], ) = _generateKeyPair("xmode-ver-add-1");
        (newKeys[1], ) = _generateKeyPair("xmode-ver-add-2");
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "xmode-ver-add-next"
        );

        bytes32 addMsgHash = _buildAddVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            addMsgHash
        );
        bytes memory payload = Codec.encodeKeyManagement(
            Codec.KeyType.Verification,
            alicePubkey,
            nextPq,
            sig,
            newKeys
        );

        // Attacker submits the same signed payload to refreshKeys. The digest
        // the wallet rebuilds uses REFRESH_VERIFICATION_KEYS_TAG, which does
        // not match the addKeys-domain signature.
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(payload);

        // Seeded keys still present; nothing was cleared.
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);
    }

    function test_signatureReplay_refreshVerificationCannotBeLiftedToAdd()
        public
    {
        // The mirror direction: a refreshKeys-signed payload submitted to
        // addKeys must also revert. Less destructive than the other direction
        // (no clear happens), but the cross-mode invariant must hold both ways.
        _seedVerificationKeys(3);

        WOTSPlus.WinternitzAddress[]
            memory newKeys = new WOTSPlus.WinternitzAddress[](2);
        (newKeys[0], ) = _generateKeyPair("xmode-ver-ref-1");
        (newKeys[1], ) = _generateKeyPair("xmode-ver-ref-2");
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "xmode-ver-ref-next"
        );

        bytes32 refreshMsgHash = _buildReplenishVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            refreshMsgHash
        );
        bytes memory payload = Codec.encodeKeyManagement(
            Codec.KeyType.Verification,
            alicePubkey,
            nextPq,
            sig,
            newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.addKeys(payload);
    }

    function test_signatureReplay_addRecoveryCannotBeLiftedToRefresh() public {
        // Same cross-mode property for the Recovery keyset. This is the most
        // dangerous direction in the entire audit finding: a successful lift
        // would wipe the owner's recovery keys and replace them with the
        // attacker-supplied batch, handing future-recoverWallet authority to
        // the attacker.
        WOTSPlus.WinternitzAddress[]
            memory newKeys = new WOTSPlus.WinternitzAddress[](1);
        (newKeys[0], ) = _generateKeyPair("xmode-rec-add-1");
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "xmode-rec-add-next"
        );

        bytes32 addMsgHash = _buildAddRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            addMsgHash
        );
        bytes memory payload = Codec.encodeKeyManagement(
            Codec.KeyType.Recovery,
            alicePubkey,
            nextPq,
            sig,
            newKeys
        );

        uint256 recBefore = wallet.keyCount(Codec.KeyType.Recovery);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(payload);

        // Recovery keyset untouched.
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), recBefore);
    }

    function test_signatureReplay_refreshRecoveryCannotBeLiftedToAdd() public {
        WOTSPlus.WinternitzAddress[]
            memory newKeys = new WOTSPlus.WinternitzAddress[](1);
        (newKeys[0], ) = _generateKeyPair("xmode-rec-ref-1");
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "xmode-rec-ref-next"
        );

        bytes32 refreshMsgHash = _buildReplenishRecoveryKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            refreshMsgHash
        );
        bytes memory payload = Codec.encodeKeyManagement(
            Codec.KeyType.Recovery,
            alicePubkey,
            nextPq,
            sig,
            newKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.addKeys(payload);
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
}
