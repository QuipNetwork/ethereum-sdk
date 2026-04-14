// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipWallet_addVerificationKeys is QuipWalletTest {
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

    // ── Happy paths ──────────────────────────────────────────────────

    function test_addVerificationKeys_addsKeys() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("add-3", 3);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-next-1");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, newKeys));

        assertEq(wallet.getVerificationKeyCount(), 3);
        for (uint256 i = 0; i < 3; i++) {
            assertTrue(
                wallet.isVerificationKey(newKeys[i])
            );
        }
    }

    function test_addVerificationKeys_rotatesPqOwner() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("add-rotate", 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-next-2");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, newKeys));

        (bytes32 ps, bytes32 ph) = wallet.pqOwner();
        assertEq(ps, nextPq.publicSeed);
        assertEq(ph, nextPq.publicKeyHash);
    }

    function test_addVerificationKeys_emitsVerificationKeysAdded() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("add-ev", 2);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-next-ev");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.recordLogs();
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, newKeys));

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipWallet.VerificationKeysAdded.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "VerificationKeysAdded not emitted");
    }

    function test_addVerificationKeys_appendsToExisting() public {
        _seedVerificationKeys(2);
        assertEq(wallet.getVerificationKeyCount(), 2);

        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("add-more", 3);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-append-next");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, newKeys));

        assertEq(wallet.getVerificationKeyCount(), 5);
    }

    // ── Reverts ──────────────────────────────────────────────────────

    function test_addVerificationKeys_revertsWhen_callerNotOwner() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("add-auth", 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-auth-next");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, newKeys));
    }

    function test_addVerificationKeys_revertsWhen_invalidSignature() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("add-bad-sig", 1);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-bad-next");

        (, bytes32 wrongKey) = _generateKeyPair("wrong-signer");
        WOTSPlus.WinternitzElements memory badSig = _sign(wrongKey, keccak256("wrong-digest"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, badSig, newKeys));
    }

    function test_addVerificationKeys_revertsWhen_nextPqOwnerSeedIsZero() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("zs", 1);
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("x"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(zeroPq, sig, newKeys));
    }

    function test_addVerificationKeys_revertsWhen_nextPqOwnerHashIsZero() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("zh", 1);
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("x"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(zeroPq, sig, newKeys));
    }

    function test_addVerificationKeys_revertsWhen_pqOwnerReuse() public {
        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("reuse", 1);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, keccak256("x"));

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.PqOwnerReuse.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(alicePubkey, sig, newKeys));
    }

    function test_addVerificationKeys_revertsWhen_emptyArray() public {
        WOTSPlus.WinternitzAddress[] memory empty = new WOTSPlus.WinternitzAddress[](0);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-empty-next");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, empty
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.EmptyVerificationKeys.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, empty));
    }

    function test_addVerificationKeys_revertsWhen_capacityExceeded() public {
        _seedVerificationKeys(9);
        WOTSPlus.WinternitzAddress[] memory newKeys = _genKeys("cap-overflow", 2);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-cap-next");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, newKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.VerificationKeyLimitExceeded.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, newKeys));
    }

    function test_addVerificationKeys_revertsWhen_keyHasZeroSeed() public {
        WOTSPlus.WinternitzAddress[] memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-zseed-next");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, badKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, badKeys));
    }

    function test_addVerificationKeys_revertsWhen_keyHasZeroHash() public {
        WOTSPlus.WinternitzAddress[] memory badKeys = new WOTSPlus.WinternitzAddress[](1);
        badKeys[0] = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-zhash-next");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, badKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, badKeys));
    }

    function test_addVerificationKeys_revertsWhen_duplicateInBatch() public {
        WOTSPlus.WinternitzAddress[] memory dupKeys = new WOTSPlus.WinternitzAddress[](2);
        (dupKeys[0],) = _generateKeyPair("dup-batch");
        dupKeys[1] = dupKeys[0];
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-dup-next");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, dupKeys
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateVerificationKey.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, dupKeys));
    }

    function test_addVerificationKeys_revertsWhen_duplicateWithExisting() public {
        (WOTSPlus.WinternitzAddress[] memory seeded,) = _seedVerificationKeys(2);

        WOTSPlus.WinternitzAddress[] memory dup = new WOTSPlus.WinternitzAddress[](1);
        dup[0] = seeded[0]; // already in set
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("addvk-dup-existing-next");

        bytes32 msgHash = _buildVerificationKeysMessageHash(
            address(wallet), alicePubkey, nextPq, dup
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateVerificationKey.selector);
        wallet.addVerificationKeys(Codec.encodeKeyManagement(nextPq, sig, dup));
    }
}
