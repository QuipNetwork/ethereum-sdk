// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_transferOwnership is QuipWalletTest {
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event PqOwnerRotated(WOTSPlus.WinternitzAddress oldPqOwner, WOTSPlus.WinternitzAddress newPqOwner);

    function _buildPayload(
        WOTSPlus.WinternitzAddress memory nextPq,
        address newOwner
    ) internal view returns (bytes memory) {
        bytes32 msgHash = _buildTransferOwnershipMessageHash(address(wallet), alicePubkey, nextPq, newOwner);
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);
        return Codec.encodeOwnershipTransfer(nextPq, sig, newOwner);
    }

    function test_transferOwnership_transfersOwnership() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        assertEq(wallet.owner(), BOB);
    }

    function test_transferOwnership_rotatesPqOwner() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.prank(ALICE);
        wallet.transferOwnership(payload);

        (bytes32 seed, bytes32 hash) = wallet.pqOwner();
        assertEq(seed, nextPq.publicSeed);
        assertEq(hash, nextPq.publicKeyHash);
    }

    function test_transferOwnership_emitsPqOwnerRotated() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.expectEmit(false, false, false, true, address(wallet));
        emit PqOwnerRotated(alicePubkey, nextPq);

        vm.prank(ALICE);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_emitsOwnershipTransferred() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit OwnershipTransferred(ALICE, BOB);

        vm.prank(ALICE);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_classicalCalled() public {
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ClassicalTransferOwnershipDisabled.selector);
        wallet.transferOwnership(BOB);
    }

    function test_transferOwnership_revertsWhen_classicalCalledByNonOwner() public {
        vm.prank(BOB);
        vm.expectRevert(IQuipWallet.ClassicalTransferOwnershipDisabled.selector);
        wallet.transferOwnership(BOB);
    }

    function test_transferOwnership_revertsWhen_callerNotOwner() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_nextPqOwnerSeedIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        bytes memory payload = _buildPayload(zeroPq, BOB);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_nextPqOwnerHashIsZero() public {
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32("non-empty"),
            publicKeyHash: bytes32(0)
        });
        bytes memory payload = _buildPayload(zeroPq, BOB);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_pqOwnerReuse() public {
        bytes memory payload = _buildPayload(alicePubkey, BOB);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.PqOwnerReuse.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_invalidSignature() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        WOTSPlus.WinternitzElements memory badSig = _sign(alicePrivateKey, keccak256("wrong message"));
        bytes memory payload = Codec.encodeOwnershipTransfer(nextPq, badSig, BOB);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.transferOwnership(payload);
    }

    function test_transferOwnership_revertsWhen_newOwnerIsZero() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, address(0));

        vm.prank(ALICE);
        vm.expectRevert(SoladyOwnable.NewOwnerIsZeroAddress.selector);
        wallet.transferOwnership(payload);
    }
}
