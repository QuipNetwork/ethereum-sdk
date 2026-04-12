// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_completeOwnershipHandover is QuipWalletTest {
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event PqOwnerRotated(WOTSPlus.WinternitzAddress oldPqOwner, WOTSPlus.WinternitzAddress newPqOwner);

    function _buildPayload(
        WOTSPlus.WinternitzAddress memory nextPq,
        address pendingOwner
    ) internal view returns (bytes memory) {
        bytes32 msgHash = _buildCompleteOwnershipHandoverMessageHash(
            address(wallet), alicePubkey, nextPq, pendingOwner
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);
        return Codec.encodeOwnershipTransfer(nextPq, sig, pendingOwner);
    }

    function _requestHandover(address pendingOwner) internal {
        vm.prank(pendingOwner);
        wallet.requestOwnershipHandover();
    }

    function test_completeOwnershipHandover_completesHandover() public {
        _requestHandover(BOB);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(payload);

        assertEq(wallet.owner(), BOB);
    }

    function test_completeOwnershipHandover_rotatesPqOwner() public {
        _requestHandover(BOB);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(payload);

        (bytes32 seed, bytes32 hash) = wallet.pqOwner();
        assertEq(seed, nextPq.publicSeed);
        assertEq(hash, nextPq.publicKeyHash);
    }

    function test_completeOwnershipHandover_emitsPqOwnerRotated() public {
        _requestHandover(BOB);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.expectEmit(false, false, false, true, address(wallet));
        emit PqOwnerRotated(alicePubkey, nextPq);

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_emitsOwnershipTransferred() public {
        _requestHandover(BOB);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit OwnershipTransferred(ALICE, BOB);

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_classicalCalled() public {
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ClassicalCompleteOwnershipHandoverDisabled.selector);
        wallet.completeOwnershipHandover(BOB);
    }

    function test_completeOwnershipHandover_revertsWhen_classicalCalledByNonOwner() public {
        vm.prank(BOB);
        vm.expectRevert(IQuipWallet.ClassicalCompleteOwnershipHandoverDisabled.selector);
        wallet.completeOwnershipHandover(BOB);
    }

    function test_completeOwnershipHandover_revertsWhen_callerNotOwner() public {
        _requestHandover(BOB);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_noHandoverRequest() public {
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.prank(ALICE);
        vm.expectRevert(SoladyOwnable.NoHandoverRequest.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_handoverExpired() public {
        _requestHandover(BOB);
        // Solady default handover validity is 48 hours.
        vm.warp(block.timestamp + 48 hours + 1);

        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        bytes memory payload = _buildPayload(nextPq, BOB);

        vm.prank(ALICE);
        vm.expectRevert(SoladyOwnable.NoHandoverRequest.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_nextPqOwnerSeedIsZero() public {
        _requestHandover(BOB);
        WOTSPlus.WinternitzAddress memory zeroPq = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32("non-empty")
        });
        bytes memory payload = _buildPayload(zeroPq, BOB);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroValuePqOwner.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_pqOwnerReuse() public {
        _requestHandover(BOB);
        bytes memory payload = _buildPayload(alicePubkey, BOB);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.PqOwnerReuse.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_invalidSignature() public {
        _requestHandover(BOB);
        (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("next-pq");
        WOTSPlus.WinternitzElements memory badSig = _sign(alicePrivateKey, keccak256("wrong message"));
        bytes memory payload = Codec.encodeOwnershipTransfer(nextPq, badSig, BOB);

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.completeOwnershipHandover(payload);
    }
}
