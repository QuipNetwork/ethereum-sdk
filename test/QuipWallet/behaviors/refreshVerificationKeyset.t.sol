// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipWallet_refreshVerificationKeyset is QuipWalletTest {
    function _genKeys(string memory tag, uint256 n)
        internal
        pure
        returns (WOTSPlus.WinternitzAddress[] memory keys)
    {
        keys = new WOTSPlus.WinternitzAddress[](n);
        for (uint256 i = 0; i < n; i++) {
            (keys[i],) = WOTSPlus.generateKeyPair(keccak256(abi.encodePacked(tag, i)));
        }
    }

    function _refresh(
        WOTSPlus.WinternitzAddress[] memory newKeys,
        string memory nextTag
    ) internal returns (WOTSPlus.WinternitzAddress memory nextPq) {
        (nextPq,) = _generateKeyPair(keccak256(abi.encodePacked(nextTag)));
        bytes32 msgHash = _buildVerificationKeysetMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);
        vm.prank(ALICE);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, sig, newKeys));
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_refreshVerificationKeyset_fromEmpty() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-e", 3);
        _refresh(keys, "refresh-empty-next");
        assertEq(wallet.getVerificationKeyCount(), 3);
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(wallet.isVerificationKey(keys[i]));
        }
    }

    function test_refreshVerificationKeyset_fromPartial() public {
        (WOTSPlus.WinternitzAddress[] memory original,) = _seedVerificationKeyset(2);
        WOTSPlus.WinternitzAddress[] memory fresh = _genKeys("refresh-p", 5);
        _refresh(fresh, "refresh-partial-next");

        assertEq(wallet.getVerificationKeyCount(), 5);
        for (uint256 i = 0; i < 2; i++) {
            assertFalse(
                wallet.isVerificationKey(original[i])
            );
        }
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(wallet.isVerificationKey(fresh[i]));
        }
    }

    function test_refreshVerificationKeyset_fromFull() public {
        (WOTSPlus.WinternitzAddress[] memory original,) = _seedVerificationKeyset(10);
        WOTSPlus.WinternitzAddress[] memory fresh = _genKeys("refresh-f", 1);
        _refresh(fresh, "refresh-full-next");

        assertEq(wallet.getVerificationKeyCount(), 1);
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(
                wallet.isVerificationKey(original[i])
            );
        }
        assertTrue(wallet.isVerificationKey(fresh[0]));
    }

    function test_refreshVerificationKeyset_rotatesPqOwner() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-rot", 2);
        WOTSPlus.WinternitzAddress memory nextPq = _refresh(keys, "refresh-rot-next");
        (bytes32 ps, bytes32 ph) = wallet.pqOwner();
        assertEq(ps, nextPq.publicSeed);
        assertEq(ph, nextPq.publicKeyHash);
    }

    function test_refreshVerificationKeyset_emitsEvent() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-ev", 2);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("refresh-ev-next");
        bytes32 msgHash = _buildVerificationKeysetMessageHash(
            address(wallet), alicePubkey, nextPq, keys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, sig, keys));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.VerificationKeysetRefreshed.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "VerificationKeysetRefreshed not emitted");
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_refreshVerificationKeyset_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-auth", 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("refresh-auth-next");
        bytes32 msgHash = _buildVerificationKeysetMessageHash(
            address(wallet), alicePubkey, nextPq, keys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, sig, keys));
    }

    function test_refreshVerificationKeyset_revertsWhen_invalidSignature() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-bad", 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("refresh-bad-next");
        (, bytes32 wrong) = _generateKeyPair("refresh-wrong");
        WOTSPlus.WinternitzElements memory badSig = _sign(wrong, keccak256("x"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, badSig, keys));
    }

    function test_refreshVerificationKeyset_revertsWhen_nextPqOwnerSeedIsZero() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-zs", 1);
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("x")
        });
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("d"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(zeroPq, sig, keys));
    }

    function test_refreshVerificationKeyset_revertsWhen_nextPqOwnerHashIsZero() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-zh", 1);
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("x"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("d"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(zeroPq, sig, keys));
    }

    function test_refreshVerificationKeyset_revertsWhen_pqOwnerReuse() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-reuse", 1);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("x"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.PqOwnerReuse.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(alicePubkey, sig, keys));
    }

    function test_refreshVerificationKeyset_revertsWhen_emptyArray() public {
        WOTSPlus.WinternitzAddress[] memory empty = new WOTSPlus.WinternitzAddress[](0);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("refresh-empty-next");
        bytes32 msgHash = _buildVerificationKeysetMessageHash(
            address(wallet), alicePubkey, nextPq, empty
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.EmptyVerificationKeys.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, sig, empty));
    }

    function test_refreshVerificationKeyset_revertsWhen_newBatchExceedsMax() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-over", 11);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("refresh-over-next");
        bytes32 msgHash = _buildVerificationKeysetMessageHash(
            address(wallet), alicePubkey, nextPq, keys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.VerificationKeyLimitExceeded.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, sig, keys));
    }

    function test_refreshVerificationKeyset_revertsWhen_duplicateInBatch() public {
        WOTSPlus.WinternitzAddress[] memory dup = new WOTSPlus.WinternitzAddress[](2);
        (dup[0],) = _generateKeyPair("refresh-dup");
        dup[1] = dup[0];
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("refresh-dup-next");
        bytes32 msgHash = _buildVerificationKeysetMessageHash(
            address(wallet), alicePubkey, nextPq, dup
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateVerificationKey.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, sig, dup));
    }

    function test_refreshVerificationKeyset_revertsWhen_keyHasZeroSeed() public {
        WOTSPlus.WinternitzAddress[] memory bad = new WOTSPlus.WinternitzAddress[](1);
        bad[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("x")
        });
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("refresh-zseed-next");
        bytes32 msgHash = _buildVerificationKeysetMessageHash(
            address(wallet), alicePubkey, nextPq, bad
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, sig, bad));
    }

    function test_refreshVerificationKeyset_revertsWhen_keyHasZeroHash() public {
        WOTSPlus.WinternitzAddress[] memory bad = new WOTSPlus.WinternitzAddress[](1);
        bad[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("x"),
            publicKeyHash: bytes32(0)
        });
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("refresh-zhash-next");
        bytes32 msgHash = _buildVerificationKeysetMessageHash(
            address(wallet), alicePubkey, nextPq, bad
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.refreshVerificationKeyset(Codec.encodeKeyManagement(nextPq, sig, bad));
    }
}
