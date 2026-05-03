// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @title Multi-Operation Key Chain Scenario Test
/// @dev Verifies an unbroken WOTS+ key chain across 9 different operation
///      types spanning every keyset:
///        1. execute (transfer)
///        2. execute (call)
///        3. refreshKeys(Recovery)
///        4. execute
///        5. addKeys(Verification)              — extends to the Verification keyset
///        6. isValidSignature (ERC-1271)         — stateless; uses a verification key
///        7. replaceKeyAt(Verification)          — rotates a verification key
///        8. transferOwnership                   — wipes the verification keyset
///        9. execute (as new owner BOB)
///      Each state-mutating operation rotates the PQ key; the next uses the rotated key.
contract QuipWallet_multiOperationKeyChain is QuipWalletTest {
    DummyContract public dummy;

    WOTSPlus.WinternitzAddress internal currentPq;
    bytes32 internal currentPrivKey;

    function setUp() public override {
        super.setUp();
        dummy = new DummyContract();
    }

    /// @dev Rotate key, return new private key.
    function _advance(
        bytes32 seed
    )
        internal
        returns (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPrivKey)
    {
        (nextPq, nextPrivKey) = _generateKeyPair(seed);
    }

    /// @dev 7-operation key chain across different op types.
    function test_simulation_multiOperationKeyChain() public {
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // ── Op 1: execute (ETH transfer) ────────────────────────────
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("chain-1-execute-transfer");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet),
                currentPq,
                nextPq,
                BOB,
                0.05 ether,
                "",
                fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(
                currentPrivKey,
                msgHash
            );

            uint256 bobBal = BOB.balance;
            vm.prank(ALICE);
            wallet.execute(
                Codec.encodeExecute(currentPq, nextPq, sig, BOB, 0.05 ether, "")
            );
            assertEq(BOB.balance, bobBal + 0.05 ether);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 2: execute (contract call) ───────────────────────────
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("chain-2-execute-call");
            bytes memory callData = abi.encodeWithSelector(
                DummyContract.setValueNoFee.selector,
                99
            );
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet),
                currentPq,
                nextPq,
                address(dummy),
                0,
                callData,
                fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(
                currentPrivKey,
                msgHash
            );

            vm.prank(ALICE);
            wallet.execute(
                Codec.encodeExecute(
                    currentPq,
                    nextPq,
                    sig,
                    address(dummy),
                    0,
                    callData
                )
            );
            assertEq(dummy.value(), 99);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 3: refreshKeys(Recovery) (keyManagement digest domain) ──
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("chain-4-replenish");
            bytes32 recBase = keccak256("chain-4-recovery-keys");
            WOTSPlus.WinternitzAddress[] memory newKeys = _generateRecoveryKeys(
                recBase,
                10
            );

            bytes32 msgHash = _buildReplenishRecoveryKeysMessageHash(
                address(wallet),
                currentPq,
                nextPq,
                newKeys
            );
            WOTSPlus.WinternitzElements memory sig = _sign(
                currentPrivKey,
                msgHash
            );

            vm.prank(ALICE);
            wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Recovery, currentPq, nextPq, sig, newKeys)
            );
            assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 4: execute (another transfer) ────────────────────────
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("chain-5-execute");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet),
                currentPq,
                nextPq,
                BOB,
                0.01 ether,
                "",
                fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(
                currentPrivKey,
                msgHash
            );

            vm.prank(ALICE);
            wallet.execute(
                Codec.encodeExecute(currentPq, nextPq, sig, BOB, 0.01 ether, "")
            );

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 5: addKeys(Verification, 3) ──────────────────────────
        //   Extends the unbroken chain to the Verification keyset. The auth
        //   rotation still runs on the Transaction keyset via the shared
        //   `keyManagement` flow; the verifier material is stored separately.
        WOTSPlus.WinternitzAddress[] memory verifierPubs = new WOTSPlus.WinternitzAddress[](3);
        bytes32[] memory verifierPrivs = new bytes32[](3);
        for (uint256 i = 0; i < 3; i++) {
            (verifierPubs[i], verifierPrivs[i]) = _generateKeyPair(
                keccak256(abi.encodePacked("chain-6-verifier", i))
            );
        }
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("chain-6-addverif");
            bytes32 msgHash = _buildVerificationKeysMessageHash(
                address(wallet),
                currentPq,
                nextPq,
                verifierPubs
            );
            WOTSPlus.WinternitzElements memory sig = _sign(
                currentPrivKey,
                msgHash
            );

            vm.prank(ALICE);
            wallet.addKeys(
                Codec.encodeKeyManagement(
                    Codec.KeyType.Verification,
                    currentPq,
                    nextPq,
                    sig,
                    verifierPubs
                )
            );
            assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 6: ERC-1271 isValidSignature (stateless — no PQ rotation) ──
        //   Uses verifierPubs[0] to sign an ERC-1271 hash AND the classical
        //   owner's ECDSA over the raw hash. View-only — the PQ chain is
        //   untouched and Op 8 continues signing with the Op 6 nextPq.
        {
            bytes32 erc1271Hash = keccak256("chain-7-erc1271");
            bytes32 erc1271Digest = _buildErc1271MessageHash(
                address(wallet),
                verifierPubs[0],
                erc1271Hash
            );
            WOTSPlus.WinternitzElements memory pqSig = _sign(
                verifierPrivs[0],
                erc1271Digest
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ALICE_KEY, erc1271Hash);
            bytes memory ecdsa = abi.encodePacked(r, s, v);

            bytes4 result = wallet.isValidSignature(
                erc1271Hash,
                Codec.encodeErc1271Signature(verifierPubs[0], pqSig, ecdsa)
            );
            assertEq(result, bytes4(0x1626ba7e));
        }

        // ── Op 7: replaceKeyAt(Verification, 1) ─────────────────────
        //   Swap the verifier at index 1 for a fresh key. Rotates the
        //   transaction-key chain via the shared auth rotation.
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("chain-8-replace");
            (WOTSPlus.WinternitzAddress memory replacement, ) = _generateKeyPair(
                "chain-8-verifier-replacement"
            );
            bytes32 msgHash = _buildReplaceKeyAtMessageHash(
                Codec.KeyType.Verification,
                address(wallet),
                currentPq,
                nextPq,
                1,
                replacement
            );
            WOTSPlus.WinternitzElements memory sig = _sign(
                currentPrivKey,
                msgHash
            );

            vm.prank(ALICE);
            wallet.replaceKeyAt(
                Codec.encodeReplaceKeyAt(
                    Codec.KeyType.Verification,
                    currentPq,
                    nextPq,
                    sig,
                    1,
                    replacement
                )
            );
            assertFalse(wallet.isKey(Codec.KeyType.Verification, verifierPubs[1]));
            assertTrue(wallet.isKey(Codec.KeyType.Verification, replacement));
            assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op 8: transferOwnership to BOB ──────────────────────────
        //   transferOwnership is authed by the wallet's dedicated ownershipKey
        //   (not a transaction key), and is a full re-init — the transaction key
        //   chain from prior ops is discarded here and replaced by a fresh batch
        //   under BOB's control. The verification keyset (3 keys seeded in Op 6
        //   + rotated in Op 8) is also cleared as part of the re-init.
        WOTSPlus.WinternitzAddress[5] memory bobTxnPubs;
        bytes32[5] memory bobTxnPrivs;
        WOTSPlus.WinternitzAddress[10] memory bobRecPubs;
        for (uint256 i = 0; i < 5; i++) {
            (bobTxnPubs[i], bobTxnPrivs[i]) = _generateKeyPair(
                keccak256(abi.encodePacked("chain-6-bob-txn", i))
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            (bobRecPubs[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked("chain-6-bob-rec", i))
            );
        }
        {
            (WOTSPlus.WinternitzAddress memory nextOwnership, ) = _generateKeyPair(
                "chain-6-new-ownership"
            );
            (WOTSPlus.WinternitzAddress memory newDisaster, ) = _generateKeyPair(
                "chain-6-new-disaster"
            );

            bytes32 keysHash = keccak256(
                abi.encode(newDisaster, bobTxnPubs, bobRecPubs)
            );
            bytes32 msgHash = _buildTransferOwnershipMessageHash(
                address(wallet),
                ownershipPubkey,
                nextOwnership,
                BOB,
                keysHash
            );
            WOTSPlus.WinternitzElements memory sig = _sign(
                ownershipPrivateKey,
                msgHash
            );

            vm.prank(ALICE);
            wallet.transferOwnership(
                Codec.encodeOwnershipTransfer(
                    ownershipPubkey,
                    nextOwnership,
                    sig,
                    BOB,
                    newDisaster,
                    bobTxnPubs,
                    bobRecPubs
                )
            );
            assertEq(wallet.owner(), BOB);
            // Re-init clears the verification keyset.
            assertEq(wallet.keyCount(Codec.KeyType.Verification), 0);
        }

        // ── Op 9: BOB operates with one of the freshly installed txn keys ──
        {
            currentPq = bobTxnPubs[0];
            currentPrivKey = bobTxnPrivs[0];
            (WOTSPlus.WinternitzAddress memory nextPq, ) = _advance(
                "chain-7-bob-exec"
            );
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet),
                currentPq,
                nextPq,
                BOB,
                0.01 ether,
                "",
                fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(
                currentPrivKey,
                msgHash
            );

            uint256 bobBal = BOB.balance;
            vm.prank(BOB);
            wallet.execute(
                Codec.encodeExecute(currentPq, nextPq, sig, BOB, 0.01 ether, "")
            );
            assertEq(BOB.balance, bobBal + 0.01 ether);
        }
    }

    /// @dev Chained public-API rotations while the Transaction keyset is at
    ///      `MAX_KEYS == 10`. The harness-level
    ///      `test_exposed_rotateKeys_succeedsAtFullCapacity` proves the
    ///      storage primitive's remove-then-add ordering preserves size for a
    ///      single rotation; this scenario walks every rotation-bearing
    ///      public entry point that goes through `_verifyAndRotate` and
    ///      asserts `keyCount(Transaction) == 10` after each op. A future
    ///      refactor that reorders any public path into add-then-remove (or
    ///      otherwise breaks the size invariant) would silently trip the
    ///      `MAX_KEYS` cap only when the wallet is at capacity — exactly the
    ///      production state a long-lived wallet drifts toward.
    function test_simulation_keyChain_atMaxTransactionCapacity() public {
        // ── Phase 0: Fill the Transaction keyset 5 → 10 ─────────────
        // `addKeys(Transaction, …)` auth-rotates `alicePubkey → fA` (size
        // stays 5) then appends 5 new keys (size becomes 10). The auth
        // rotation alone is at-capacity-adjacent (4→5→4→5 across remove/add)
        // so every subsequent op is the actual at-MAX regression target.
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;
        {
            WOTSPlus.WinternitzAddress[] memory fillKeys = new WOTSPlus.WinternitzAddress[](5);
            for (uint256 i = 0; i < 5; i++) {
                (fillKeys[i], ) = _generateKeyPair(
                    keccak256(abi.encodePacked("max-cap-fill", i))
                );
            }
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("max-cap-rotate-into-fill");
            // Inline keyset digest (Transaction kind has no dedicated builder
            // in QuipWalletTest, only Recovery/Verification/replaceKeyAt).
            bytes32 msgHash = Codec.keysetDigest(
                Codec.KeyType.Transaction,
                address(wallet),
                block.chainid,
                currentPq.publicSeed,
                currentPq.publicKeyHash,
                nextPq.publicSeed,
                nextPq.publicKeyHash,
                keccak256(abi.encode(fillKeys))
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.addKeys(
                Codec.encodeKeyManagement(
                    Codec.KeyType.Transaction,
                    currentPq,
                    nextPq,
                    sig,
                    fillKeys
                )
            );
            assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op A: execute at MAX (basic remove-then-add via _rotateKeys) ──
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("max-cap-op-a-execute");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet),
                currentPq,
                nextPq,
                BOB,
                0.01 ether,
                "",
                fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            WOTSPlus.WinternitzAddress memory consumed = currentPq;
            vm.prank(ALICE);
            wallet.execute(
                Codec.encodeExecute(currentPq, nextPq, sig, BOB, 0.01 ether, "")
            );
            assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, consumed));
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op B: replaceKeyAt(Recovery) — auth rotation while at MAX ───
        // Recovery is independently at MAX (10) from init, so this also
        // confirms the target keyset's at-capacity replace works through the
        // public path — even though the Transaction-set size is what we're
        // primarily locking down here.
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("max-cap-op-b-replace-rec");
            (WOTSPlus.WinternitzAddress memory replacement, ) = _generateKeyPair(
                "max-cap-op-b-rec-replacement"
            );
            bytes32 msgHash = _buildReplaceKeyAtMessageHash(
                Codec.KeyType.Recovery,
                address(wallet),
                currentPq,
                nextPq,
                0,
                replacement
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            WOTSPlus.WinternitzAddress memory consumed = currentPq;
            vm.prank(ALICE);
            wallet.replaceKeyAt(
                Codec.encodeReplaceKeyAt(
                    Codec.KeyType.Recovery,
                    currentPq,
                    nextPq,
                    sig,
                    0,
                    replacement
                )
            );
            assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
            assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, consumed));
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op C: addKeys(Verification, 3) — extends a different keyset ──
        // The Transaction-set rotation runs the same primitive; appending to
        // a sibling keyset (Verification) doesn't widen the auth set.
        WOTSPlus.WinternitzAddress[] memory verifierPubs = new WOTSPlus.WinternitzAddress[](3);
        for (uint256 i = 0; i < 3; i++) {
            (verifierPubs[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked("max-cap-op-c-verifier", i))
            );
        }
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("max-cap-op-c-add-verif");
            bytes32 msgHash = _buildVerificationKeysMessageHash(
                address(wallet),
                currentPq,
                nextPq,
                verifierPubs
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            WOTSPlus.WinternitzAddress memory consumed = currentPq;
            vm.prank(ALICE);
            wallet.addKeys(
                Codec.encodeKeyManagement(
                    Codec.KeyType.Verification,
                    currentPq,
                    nextPq,
                    sig,
                    verifierPubs
                )
            );
            assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
            assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, consumed));
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op D: replaceKeyAt(Verification) at single-key edge of Verification ──
        // Verification has 3 entries; replaces idx=0. Combined with Op B,
        // this proves replaceKeyAt rotates the Transaction auth set without
        // size drift regardless of which target keyset is being touched.
        {
            (
                WOTSPlus.WinternitzAddress memory nextPq,
                bytes32 nextPriv
            ) = _advance("max-cap-op-d-replace-verif");
            (WOTSPlus.WinternitzAddress memory replacement, ) = _generateKeyPair(
                "max-cap-op-d-verif-replacement"
            );
            bytes32 msgHash = _buildReplaceKeyAtMessageHash(
                Codec.KeyType.Verification,
                address(wallet),
                currentPq,
                nextPq,
                0,
                replacement
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            WOTSPlus.WinternitzAddress memory consumed = currentPq;
            vm.prank(ALICE);
            wallet.replaceKeyAt(
                Codec.encodeReplaceKeyAt(
                    Codec.KeyType.Verification,
                    currentPq,
                    nextPq,
                    sig,
                    0,
                    replacement
                )
            );
            assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
            assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);
            assertFalse(wallet.isKey(Codec.KeyType.Verification, verifierPubs[0]));
            assertTrue(wallet.isKey(Codec.KeyType.Verification, replacement));
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, consumed));
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // ── Op E: final execute — sanity check the chain is still live ──
        {
            (WOTSPlus.WinternitzAddress memory nextPq, ) = _advance(
                "max-cap-op-e-final-execute"
            );
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet),
                currentPq,
                nextPq,
                BOB,
                0.01 ether,
                "",
                fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            WOTSPlus.WinternitzAddress memory consumed = currentPq;
            vm.prank(ALICE);
            wallet.execute(
                Codec.encodeExecute(currentPq, nextPq, sig, BOB, 0.01 ether, "")
            );
            assertEq(wallet.keyCount(Codec.KeyType.Transaction), 10);
            assertFalse(wallet.isKey(Codec.KeyType.Transaction, consumed));
            assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
        }
    }
}
