// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipWallet_replaceVerificationKeyAt is QuipWalletTest {
    function _replace(
        uint256 index,
        WOTSPlus.WinternitzAddress memory newKey,
        string memory nextTag
    ) internal returns (WOTSPlus.WinternitzAddress memory nextPq) {
        (nextPq,) = _generateKeyPair(keccak256(abi.encodePacked(nextTag)));
        bytes32 msgHash = _buildVerificationKeysReplaceMessageHash(
            address(wallet), alicePubkey, nextPq, index, newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);
        vm.prank(ALICE);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, index, newKey)
        );
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_replaceVerificationKeyAt_replacesAtIndex0() public {
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeys(3);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-0");

        _replace(0, newKey, "replace-0-next");

        assertEq(wallet.getVerificationKeyCount(), 3);
        assertFalse(
            wallet.isVerificationKey(seeded[0])
        );
        assertTrue(wallet.isVerificationKey(newKey));
        assertTrue(
            wallet.isVerificationKey(seeded[1])
        );
        assertTrue(
            wallet.isVerificationKey(seeded[2])
        );
    }

    function test_replaceVerificationKeyAt_replacesAtMiddle() public {
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeys(3);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-1");

        _replace(1, newKey, "replace-1-next");

        assertFalse(
            wallet.isVerificationKey(seeded[1])
        );
        assertTrue(wallet.isVerificationKey(newKey));
    }

    function test_replaceVerificationKeyAt_replacesAtLast() public {
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeys(3);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-2");

        _replace(2, newKey, "replace-2-next");

        assertFalse(
            wallet.isVerificationKey(seeded[2])
        );
        assertTrue(wallet.isVerificationKey(newKey));
    }

    function test_replaceVerificationKeyAt_replacesInEagerPhase() public {
        // Seed 5 → lazy phase transitions to eager at 4th add.
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeys(5);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-eager");

        _replace(3, newKey, "replace-eager-next");

        assertEq(wallet.getVerificationKeyCount(), 5);
        assertFalse(
            wallet.isVerificationKey(seeded[3])
        );
        assertTrue(wallet.isVerificationKey(newKey));
    }

    function test_replaceVerificationKeyAt_rotatesPqOwner() public {
        _seedVerificationKeys(2);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-rot");
        WOTSPlus.WinternitzAddress memory nextPq = _replace(0, newKey, "replace-rot-next");

        (bytes32 ps, bytes32 ph) = wallet.pqOwner();
        assertEq(ps, nextPq.publicSeed);
        assertEq(ph, nextPq.publicKeyHash);
    }

    function test_replaceVerificationKeyAt_emitsEvent() public {
        _seedVerificationKeys(2);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-ev");
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("replace-ev-next");

        bytes32 msgHash = _buildVerificationKeysReplaceMessageHash(
            address(wallet), alicePubkey, nextPq, 0, newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, 0, newKey)
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.VerificationKeyReplaced.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "VerificationKeyReplaced not emitted");
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_replaceVerificationKeyAt_revertsWhen_callerNotOwner() public {
        _seedVerificationKeys(1);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-auth");
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("replace-auth-next");
        bytes32 msgHash = _buildVerificationKeysReplaceMessageHash(
            address(wallet), alicePubkey, nextPq, 0, newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, 0, newKey)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_indexOutOfBounds() public {
        _seedVerificationKeys(2);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-oob");
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("replace-oob-next");
        bytes32 msgHash = _buildVerificationKeysReplaceMessageHash(
            address(wallet), alicePubkey, nextPq, 5, newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.VerificationKeyIndexOutOfBounds.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, 5, newKey)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_setEmpty() public {
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-empty");
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("replace-empty-next");
        bytes32 msgHash = _buildVerificationKeysReplaceMessageHash(
            address(wallet), alicePubkey, nextPq, 0, newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.VerificationKeyIndexOutOfBounds.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, 0, newKey)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_invalidSignature() public {
        _seedVerificationKeys(1);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-bad");
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("replace-bad-next");
        (, bytes32 wrong) = _generateKeyPair("replace-wrong");
        WOTSPlus.WinternitzElements memory badSig = _sign(wrong, keccak256("x"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, badSig, 0, newKey)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_nextPqOwnerSeedIsZero() public {
        _seedVerificationKeys(1);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-zns");
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("x")
        });
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("d"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(zeroPq, sig, 0, newKey)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_nextPqOwnerHashIsZero() public {
        _seedVerificationKeys(1);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-znh");
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("x"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("d"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(zeroPq, sig, 0, newKey)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_pqOwnerReuse() public {
        _seedVerificationKeys(1);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-reuse");
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("d"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.PqOwnerReuse.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(alicePubkey, sig, 0, newKey)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_newKeySeedIsZero() public {
        _seedVerificationKeys(1);
        WOTSPlus.WinternitzAddress memory bad = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("x")
        });
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("replace-nks-next");
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("d"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, 0, bad)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_newKeyHashIsZero() public {
        _seedVerificationKeys(1);
        WOTSPlus.WinternitzAddress memory bad = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("x"),
            publicKeyHash: bytes32(0)
        });
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("replace-nkh-next");
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("d"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, 0, bad)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_newKeyAlreadyInSet() public {
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeys(2);

        // Replace index 0 with the key already at index 1.
        WOTSPlus.WinternitzAddress memory dup = seeded[1];
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("replace-dup-next");
        bytes32 msgHash = _buildVerificationKeysReplaceMessageHash(
            address(wallet), alicePubkey, nextPq, 0, dup
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateVerificationKey.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, 0, dup)
        );
    }

    function test_replaceVerificationKeyAt_revertsWhen_digestIndexMismatch() public {
        _seedVerificationKeys(2);
        (WOTSPlus.WinternitzAddress memory newKey,) = _generateKeyPair("replace-mismatch");
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("replace-mismatch-next");

        // Sign for index 0, submit for index 1.
        bytes32 msgHash = _buildVerificationKeysReplaceMessageHash(
            address(wallet), alicePubkey, nextPq, 0, newKey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.replaceVerificationKeyAt(
            Codec.encodeVerificationKeysReplace(nextPq, sig, 1, newKey)
        );
    }
}
