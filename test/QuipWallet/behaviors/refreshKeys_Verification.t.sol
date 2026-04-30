// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

contract QuipWallet_refreshKeys_Verification is QuipWalletTest {
    function _genKeys(
        string memory tag,
        uint256 n
    ) internal pure returns (WOTSPlus.WinternitzAddress[] memory keys) {
        keys = new WOTSPlus.WinternitzAddress[](n);
        for (uint256 i = 0; i < n; i++) {
            (keys[i], ) = WOTSPlus.generateKeyPair(
                keccak256(abi.encodePacked(tag, i))
            );
        }
    }

    function _refresh(
        WOTSPlus.WinternitzAddress[] memory newKeys,
        string memory nextTag
    ) internal returns (WOTSPlus.WinternitzAddress memory nextPq) {
        (nextPq, ) = _generateKeyPair(keccak256(abi.encodePacked(nextTag)));
        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );
        vm.prank(ALICE);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, newKeys)
        );
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_refreshKeys_Verification_fromEmpty() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-e", 3);
        _refresh(keys, "refresh-empty-next");
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Verification, keys[i]));
        }
    }

    function test_refreshKeys_Verification_fromPartial() public {
        (
            WOTSPlus.WinternitzAddress[] memory original,

        ) = _seedVerificationKeys(2);
        WOTSPlus.WinternitzAddress[] memory fresh = _genKeys("refresh-p", 5);
        _refresh(fresh, "refresh-partial-next");

        assertEq(wallet.keyCount(Codec.KeyType.Verification), 5);
        for (uint256 i = 0; i < 2; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Verification, original[i]));
        }
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(wallet.isKey(Codec.KeyType.Verification, fresh[i]));
        }
    }

    function test_refreshKeys_Verification_fromFull() public {
        (
            WOTSPlus.WinternitzAddress[] memory original,

        ) = _seedVerificationKeys(10);
        WOTSPlus.WinternitzAddress[] memory fresh = _genKeys("refresh-f", 1);
        _refresh(fresh, "refresh-full-next");

        assertEq(wallet.keyCount(Codec.KeyType.Verification), 1);
        for (uint256 i = 0; i < 10; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Verification, original[i]));
        }
        assertTrue(wallet.isKey(Codec.KeyType.Verification, fresh[0]));
    }

    function test_refreshKeys_Verification_rotatesPqOwner() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-rot", 2);
        WOTSPlus.WinternitzAddress memory nextPq = _refresh(
            keys,
            "refresh-rot-next"
        );
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPq));
    }

    function test_refreshKeys_Verification_emitsEvent() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-ev", 2);
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "refresh-ev-next"
        );
        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            keys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, keys)
        );

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.KeysRefreshed.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "KeysRefreshed not emitted");
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_refreshKeys_Verification_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-auth", 1);
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "refresh-auth-next"
        );
        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            keys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, keys)
        );
    }

    function test_refreshKeys_Verification_revertsWhen_invalidSignature()
        public
    {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-bad", 1);
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "refresh-bad-next"
        );
        (, bytes32 wrong) = _generateKeyPair("refresh-wrong");
        WOTSPlus.WinternitzElements memory badSig = _sign(
            wrong,
            keccak256("x")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, badSig, keys)
        );
    }

    function test_refreshKeys_Verification_revertsWhen_nextPqOwnerSeedIsZero()
        public
    {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-zs", 1);
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("x")
        });
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            keccak256("d")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, zeroPq, sig, keys)
        );
    }

    function test_refreshKeys_Verification_revertsWhen_nextPqOwnerHashIsZero()
        public
    {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-zh", 1);
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("x"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            keccak256("d")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, zeroPq, sig, keys)
        );
    }

    function test_refreshKeys_Verification_revertsWhen_pqOwnerReuse() public {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-reuse", 1);
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            keccak256("x")
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.SameKey.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, alicePubkey, sig, keys)
        );
    }

    function test_refreshKeys_Verification_revertsWhen_emptyArray() public {
        WOTSPlus.WinternitzAddress[]
            memory empty = new WOTSPlus.WinternitzAddress[](0);
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "refresh-empty-next"
        );
        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            empty
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.EmptyKeys.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, empty)
        );
    }

    function test_refreshKeys_Verification_revertsWhen_newBatchExceedsMax()
        public
    {
        WOTSPlus.WinternitzAddress[] memory keys = _genKeys("refresh-over", 11);
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "refresh-over-next"
        );
        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            keys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ExceedsCapacity.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, keys)
        );
    }

    function test_refreshKeys_Verification_revertsWhen_duplicateInBatch()
        public
    {
        WOTSPlus.WinternitzAddress[]
            memory dup = new WOTSPlus.WinternitzAddress[](2);
        (dup[0], ) = _generateKeyPair("refresh-dup");
        dup[1] = dup[0];
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "refresh-dup-next"
        );
        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            dup
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.KeyInUse.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, dup)
        );
    }

    function test_refreshKeys_Verification_revertsWhen_keyHasZeroSeed() public {
        WOTSPlus.WinternitzAddress[]
            memory bad = new WOTSPlus.WinternitzAddress[](1);
        bad[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("x")
        });
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "refresh-zseed-next"
        );
        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            bad
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, bad)
        );
    }

    function test_refreshKeys_Verification_revertsWhen_keyHasZeroHash() public {
        WOTSPlus.WinternitzAddress[]
            memory bad = new WOTSPlus.WinternitzAddress[](1);
        bad[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("x"),
            publicKeyHash: bytes32(0)
        });
        (WOTSPlus.WinternitzAddress memory nextPq, ) = _generateKeyPair(
            "refresh-zhash-next"
        );
        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet),
            alicePubkey,
            nextPq,
            bad
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.refreshKeys(Codec.encodeKeyManagement(Codec.KeyType.Verification, alicePubkey, nextPq, sig, bad)
        );
    }
}
