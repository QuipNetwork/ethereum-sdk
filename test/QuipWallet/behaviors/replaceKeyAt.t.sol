// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipWallet_replaceKeyAt is QuipWalletTest {
    // ── Payload builder ──────────────────────────────────────────────

    function _buildReplacePayload(
        Codec.KeyType kind,
        uint256 index,
        WOTSPlus.WinternitzAddress memory newKey,
        string memory nextTag
    ) internal returns (WOTSPlus.WinternitzAddress memory nextPq) {
        (nextPq, ) = _generateKeyPair(keccak256(abi.encodePacked(nextTag)));
        bytes32 msgHash = _buildReplaceKeyAtMessageHash(
            kind,
            address(wallet),
            alicePubkey,
            nextPq,
            index,
            newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );
        bytes memory payload = Codec.encodeReplaceKeyAt(
            kind,
            alicePubkey,
            nextPq,
            sig,
            index,
            newKey
        );
        vm.prank(ALICE);
        wallet.replaceKeyAt(payload);
    }

    // ── Happy: Verification ──────────────────────────────────────────

    function test_replaceKeyAt_verification_replacesAtIndex0() public {
        (WOTSPlus.WinternitzAddress[] memory seeded, ) = _seedVerificationKeys(
            3
        );
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "ver-replace-0"
        );

        _buildReplacePayload(
            Codec.KeyType.Verification,
            0,
            newKey,
            "ver-replace-0-next"
        );

        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);
        assertFalse(wallet.isKey(Codec.KeyType.Verification, seeded[0]));
        assertTrue(wallet.isKey(Codec.KeyType.Verification, newKey));
        assertTrue(wallet.isKey(Codec.KeyType.Verification, seeded[1]));
        assertTrue(wallet.isKey(Codec.KeyType.Verification, seeded[2]));
    }

    function test_replaceKeyAt_verification_replacesAtLast() public {
        _seedVerificationKeys(3);
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "ver-replace-last"
        );

        _buildReplacePayload(
            Codec.KeyType.Verification,
            2,
            newKey,
            "ver-replace-last-next"
        );

        assertTrue(wallet.isKey(Codec.KeyType.Verification, newKey));
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);
    }

    function test_replaceKeyAt_verification_replacesInEagerPhase() public {
        // Seed 5 → crosses the lazy→eager transition at the 4th element.
        _seedVerificationKeys(5);
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "ver-eager"
        );

        _buildReplacePayload(
            Codec.KeyType.Verification,
            3,
            newKey,
            "ver-eager-next"
        );

        assertEq(wallet.keyCount(Codec.KeyType.Verification), 5);
        assertTrue(wallet.isKey(Codec.KeyType.Verification, newKey));
    }

    function test_replaceKeyAt_verification_rotatesAuthKey() public {
        _seedVerificationKeys(2);
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "ver-rot"
        );

        WOTSPlus.WinternitzAddress memory nextPq = _buildReplacePayload(
            Codec.KeyType.Verification,
            0,
            newKey,
            "ver-rot-next"
        );

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
    }

    // ── Happy: Recovery ──────────────────────────────────────────────

    function test_replaceKeyAt_recovery_replacesAtIndex() public {
        WOTSPlus.WinternitzAddress memory oldKey = wallet.keyAt(
            Codec.KeyType.Recovery,
            3
        );
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "rec-replace"
        );

        _buildReplacePayload(
            Codec.KeyType.Recovery,
            3,
            newKey,
            "rec-replace-next"
        );

        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        assertFalse(wallet.isKey(Codec.KeyType.Recovery, oldKey));
        assertTrue(wallet.isKey(Codec.KeyType.Recovery, newKey));
    }

    function test_replaceKeyAt_recovery_rotatesAuthKey() public {
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "rec-rot"
        );
        WOTSPlus.WinternitzAddress memory nextPq = _buildReplacePayload(
            Codec.KeyType.Recovery,
            0,
            newKey,
            "rec-rot-next"
        );
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
    }

    // ── Happy: Transaction (non-auth index) ──────────────────────────

    function test_replaceKeyAt_transaction_replacesNonAuthIndex() public {
        // alicePubkey == aliceTxnPubkeys[0] at setUp; replace the key at index 2.
        WOTSPlus.WinternitzAddress memory oldKey = aliceTxnPubkeys[2];
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, oldKey));

        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "txn-replace"
        );

        // Find oldKey's current index in the set (library may have swapped).
        uint256 idx = type(uint256).max;
        for (uint256 i = 0; i < wallet.keyCount(Codec.KeyType.Transaction); i++) {
            WOTSPlus.WinternitzAddress memory at = wallet.keyAt(
                Codec.KeyType.Transaction,
                i
            );
            if (
                at.publicSeed == oldKey.publicSeed &&
                at.publicKeyHash == oldKey.publicKeyHash
            ) {
                idx = i;
                break;
            }
        }
        require(idx != type(uint256).max, "oldKey not found");

        WOTSPlus.WinternitzAddress memory nextPq = _buildReplacePayload(
            Codec.KeyType.Transaction,
            idx,
            newKey,
            "txn-replace-next"
        );

        // Size stable at 5: auth rotation is size-neutral, replacement is size-neutral.
        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 5);
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, oldKey));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, newKey));
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
        // alicePubkey was rotated out by the auth flow.
        assertFalse(wallet.isKey(Codec.KeyType.Transaction, alicePubkey));
    }

    // ── Events ───────────────────────────────────────────────────────

    function test_replaceKeyAt_emitsKeyReplaced() public {
        _seedVerificationKeys(2);
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "emit-key"
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "emit-next"
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

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.replaceKeyAt(
            Codec.encodeReplaceKeyAt(
                Codec.KeyType.Verification,
                alicePubkey,
                nextPq,
                sig,
                0,
                newKey
            )
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.KeyReplaced.selector) {
                // `kind` is indexed — topics[1] holds the enum value.
                assertEq(
                    uint256(logs[i].topics[1]),
                    uint256(Codec.KeyType.Verification)
                );
                found = true;
                break;
            }
        }
        assertTrue(found, "KeyReplaced not emitted");
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_replaceKeyAt_revertsWhen_callerNotOwner() public {
        _seedVerificationKeys(1);
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair("r1");
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair("r1n");
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

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.replaceKeyAt(
            Codec.encodeReplaceKeyAt(
                Codec.KeyType.Verification,
                alicePubkey,
                nextPq,
                sig,
                0,
                newKey
            )
        );
    }

    function test_replaceKeyAt_revertsWhen_indexOutOfBounds() public {
        _seedVerificationKeys(2);
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair("oob");
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "oob-n"
        );
        bytes32 msgHash = _buildReplaceKeyAtMessageHash(
            Codec.KeyType.Verification,
            address(wallet),
            alicePubkey,
            nextPq,
            5,
            newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.IndexOutOfBounds.selector);
        wallet.replaceKeyAt(
            Codec.encodeReplaceKeyAt(
                Codec.KeyType.Verification,
                alicePubkey,
                nextPq,
                sig,
                5,
                newKey
            )
        );
    }

    function test_replaceKeyAt_revertsWhen_setEmpty() public {
        // Verification set is empty on fresh wallet.
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "empty"
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "empty-n"
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

        vm.prank(ALICE);
        vm.expectRevert(Keyset.IndexOutOfBounds.selector);
        wallet.replaceKeyAt(
            Codec.encodeReplaceKeyAt(
                Codec.KeyType.Verification,
                alicePubkey,
                nextPq,
                sig,
                0,
                newKey
            )
        );
    }

    function test_replaceKeyAt_revertsWhen_invalidSignature() public {
        _seedVerificationKeys(1);
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair("bad");
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "bad-n"
        );
        (, bytes32 wrong) = _generateKeyPair("bad-wrong");
        WOTSPlus.WinternitzElements memory badSig = _sign(
            wrong,
            keccak256("x")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.replaceKeyAt(
            Codec.encodeReplaceKeyAt(
                Codec.KeyType.Verification,
                alicePubkey,
                nextPq,
                badSig,
                0,
                newKey
            )
        );
    }

    function test_replaceKeyAt_revertsWhen_newKeyAlreadyInSet() public {
        (WOTSPlus.WinternitzAddress[] memory seeded, ) = _seedVerificationKeys(
            3
        );
        // Re-use an existing member as the "new" key.
        WOTSPlus.WinternitzAddress memory dupKey = seeded[1];
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "dup-n"
        );

        bytes32 msgHash = _buildReplaceKeyAtMessageHash(
            Codec.KeyType.Verification,
            address(wallet),
            alicePubkey,
            nextPq,
            0,
            dupKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        wallet.replaceKeyAt(
            Codec.encodeReplaceKeyAt(
                Codec.KeyType.Verification,
                alicePubkey,
                nextPq,
                sig,
                0,
                dupKey
            )
        );
    }

    function test_replaceKeyAt_revertsWhen_newKeyHasZeroField() public {
        _seedVerificationKeys(1);
        WOTSPlus.WinternitzAddress memory zeroKey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("x")
        });
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "zero-n"
        );
        bytes32 msgHash = _buildReplaceKeyAtMessageHash(
            Codec.KeyType.Verification,
            address(wallet),
            alicePubkey,
            nextPq,
            0,
            zeroKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.replaceKeyAt(
            Codec.encodeReplaceKeyAt(
                Codec.KeyType.Verification,
                alicePubkey,
                nextPq,
                sig,
                0,
                zeroKey
            )
        );
    }

    /// @dev Transaction-specific guard: replacing the auth key at its own index is
    ///      forbidden because the auth rotation already consumes it.
    function test_replaceKeyAt_transaction_revertsWhen_indexIsAuthKey() public {
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "txn-self"
        );

        // Find alicePubkey's index in the transaction set.
        uint256 idx = type(uint256).max;
        for (uint256 i = 0; i < wallet.keyCount(Codec.KeyType.Transaction); i++) {
            WOTSPlus.WinternitzAddress memory at = wallet.keyAt(
                Codec.KeyType.Transaction,
                i
            );
            if (
                at.publicSeed == alicePubkey.publicSeed &&
                at.publicKeyHash == alicePubkey.publicKeyHash
            ) {
                idx = i;
                break;
            }
        }
        require(idx != type(uint256).max, "alicePubkey not found");

        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "txn-self-n"
        );
        bytes32 msgHash = _buildReplaceKeyAtMessageHash(
            Codec.KeyType.Transaction,
            address(wallet),
            alicePubkey,
            nextPq,
            idx,
            newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ReplaceAuthKeyForbidden.selector);
        wallet.replaceKeyAt(
            Codec.encodeReplaceKeyAt(
                Codec.KeyType.Transaction,
                alicePubkey,
                nextPq,
                sig,
                idx,
                newKey
            )
        );
    }

    /// @dev A signature over a `Verification`-tagged digest must not verify when replayed
    ///      as a `Recovery` payload (distinct domain tag per kind).
    function test_replaceKeyAt_sigDoesNotReplayAcrossKinds() public {
        _seedVerificationKeys(1);
        (WOTSPlus.WinternitzAddress memory newKey, ) = _generateKeyPair(
            "replay"
        );
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "replay-n"
        );

        // Sign a digest tagged for Verification.
        bytes32 verDigest = _buildReplaceKeyAtMessageHash(
            Codec.KeyType.Verification,
            address(wallet),
            alicePubkey,
            nextPq,
            0,
            newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            verDigest
        );

        // Submit the same sig under a Recovery-tagged payload.
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.replaceKeyAt(
            Codec.encodeReplaceKeyAt(
                Codec.KeyType.Recovery,
                alicePubkey,
                nextPq,
                sig,
                0,
                newKey
            )
        );
    }
}
