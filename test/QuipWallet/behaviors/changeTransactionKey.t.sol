// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";
import {EnumerableWinternitzAddressSet as Keyset} from "../../../contracts/libraries/EnumerableWinternitzAddressSet.sol";

contract QuipWallet_changePqOwner is QuipWalletTest {
    function test_changePqOwner_updatesPqOwner() public {
        (WOTSPlus.WinternitzAddress memory newPubkey, ) = _generateKeyPair(
            "new-pq-owner"
        );

        bytes32 msgHash = _buildChangePqOwnerMessageHash(
            address(wallet),
            alicePubkey,
            newPubkey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.changeTransactionKey(
            Codec.encodeChangeTransactionKey(alicePubkey, newPubkey, sig)
        );

        assertTrue(wallet.isKey(Codec.KeyType.Transaction, newPubkey));
    }

    function test_changeTransactionKey_consumedKeyBecomesUnknown() public {
        // First rotation succeeds — this consumes alicePubkey from the set.
        (WOTSPlus.WinternitzAddress memory newPubkey, ) = _generateKeyPair(
            "new-pq-owner"
        );
        bytes32 msgHash = _buildChangePqOwnerMessageHash(
            address(wallet),
            alicePubkey,
            newPubkey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );
        vm.prank(ALICE);
        wallet.changeTransactionKey(
            Codec.encodeChangeTransactionKey(alicePubkey, newPubkey, sig)
        );

        // Try using the consumed key as currentKey — must revert with UnknownKey.
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "next-pq-owner"
        );
        bytes32 msgHash2 = _buildChangePqOwnerMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey
        );
        WOTSPlus.WinternitzElements memory sig2 = _sign(
            alicePrivateKey,
            msgHash2
        );
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.changeTransactionKey(
            Codec.encodeChangeTransactionKey(alicePubkey, nextPubkey, sig2)
        );
    }

    function test_changePqOwner_revertsWhen_callerNotOwner() public {
        (WOTSPlus.WinternitzAddress memory newPubkey, ) = _generateKeyPair(
            "new-pq-owner"
        );

        bytes32 msgHash = _buildChangePqOwnerMessageHash(
            address(wallet),
            alicePubkey,
            newPubkey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.changeTransactionKey(
            Codec.encodeChangeTransactionKey(alicePubkey, newPubkey, sig)
        );
    }

    function test_changePqOwner_revertsWhen_invalidSignature() public {
        (WOTSPlus.WinternitzAddress memory newPubkey, ) = _generateKeyPair(
            "new-pq-owner"
        );

        // Sign wrong message
        bytes32 wrongMsgHash = keccak256("wrong message");
        WOTSPlus.WinternitzElements memory badSig = _sign(
            alicePrivateKey,
            wrongMsgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.changeTransactionKey(
            Codec.encodeChangeTransactionKey(alicePubkey, newPubkey, badSig)
        );
    }

    function test_changePqOwner_revertsWhen_newPqOwnerSeedIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });

        bytes32 msgHash = _buildChangePqOwnerMessageHash(
            address(wallet),
            alicePubkey,
            zeroPq
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.changeTransactionKey(
            Codec.encodeChangeTransactionKey(alicePubkey, zeroPq, sig)
        );
    }

    function test_changePqOwner_revertsWhen_newPqOwnerHashIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });

        bytes32 msgHash = _buildChangePqOwnerMessageHash(
            address(wallet),
            alicePubkey,
            zeroPq
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(Keyset.ZeroValueWinternitzAddress.selector);
        wallet.changeTransactionKey(
            Codec.encodeChangeTransactionKey(alicePubkey, zeroPq, sig)
        );
    }

    function test_changePqOwner_revertsWhen_pqOwnerReuse() public {
        bytes32 msgHash = _buildChangePqOwnerMessageHash(
            address(wallet),
            alicePubkey,
            alicePubkey
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.DuplicateKey.selector);
        wallet.changeTransactionKey(
            Codec.encodeChangeTransactionKey(alicePubkey, alicePubkey, sig)
        );
    }
}
