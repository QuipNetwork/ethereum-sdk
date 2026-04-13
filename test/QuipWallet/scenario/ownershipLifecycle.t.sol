// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";

/// @title Ownership Lifecycle Scenario Test
/// @dev Full 2-step Solady ownership handover with PQ authentication:
///      ALICE operates → BOB requests handover → ALICE transfers + completes
///      → BOB is owner → BOB operates → ALICE is locked out.
contract QuipWallet_ownershipLifecycle is QuipWalletTest {
    WOTSPlus.WinternitzAddress internal currentPq;
    bytes32 internal currentPrivKey;

    /// @dev Full ownership lifecycle: operate → transfer → new owner operates.
    function test_simulation_ownershipLifecycle() public {
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // Step 1: ALICE operates the wallet normally
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
                _generateKeyPair("pre-transfer-key");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet), currentPq, nextPq, BOB, 0.05 ether, "", fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.execute(Codec.encodeExecute(nextPq, sig, BOB, 0.05 ether, ""));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // Step 2: ALICE directly transfers ownership to BOB via transferOwnership(bytes)
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
                _generateKeyPair("transfer-key");
            bytes32 msgHash = _buildTransferOwnershipMessageHash(
                address(wallet), currentPq, nextPq, BOB
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.transferOwnership(Codec.encodeOwnershipTransfer(nextPq, sig, BOB));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // After transferOwnership, owner is already BOB (Solady direct transfer)
        assertEq(wallet.owner(), BOB);

        // Step 4: BOB can now operate the wallet using the PQ key
        {
            (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("bob-exec-key");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(
                address(wallet), currentPq, nextPq, BOB, 0.01 ether, "", fee
            );
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            uint256 bobBal = BOB.balance;
            vm.prank(BOB);
            wallet.execute(Codec.encodeExecute(nextPq, sig, BOB, 0.01 ether, ""));
            assertEq(BOB.balance, bobBal + 0.01 ether);
        }

        // Step 5: ALICE is locked out — cannot call owner-gated functions
        {
            (WOTSPlus.WinternitzAddress memory dummyPq,) = _generateKeyPair("alice-locked-out");
            // Use a dummy signature; we expect Unauthorized before sig check
            WOTSPlus.WinternitzElements memory dummySig = _sign(currentPrivKey, bytes32(0));

            vm.prank(ALICE);
            vm.expectRevert(SoladyOwnable.Unauthorized.selector);
            wallet.changePqOwner(Codec.encodeChangePqOwner(dummyPq, dummySig));
        }
    }

    /// @dev 2-step handover using completeOwnershipHandover: request → complete.
    function test_simulation_twoStepHandover() public {
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // Step 1: BOB requests handover
        vm.prank(BOB);
        wallet.requestOwnershipHandover();

        // Step 2: ALICE completes the handover with PQ sig
        (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) =
            _generateKeyPair("complete-handover-key");
        bytes32 msgHash = _buildCompleteOwnershipHandoverMessageHash(
            address(wallet), currentPq, nextPq, BOB
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(Codec.encodeOwnershipTransfer(nextPq, sig, BOB));

        currentPq = nextPq;
        currentPrivKey = nextPriv;

        // Verify ownership transferred
        assertEq(wallet.owner(), BOB);

        // Step 3: BOB operates wallet
        (WOTSPlus.WinternitzAddress memory postPq,) = _generateKeyPair("bob-post-handover-key");
        bytes32 rotateHash = _buildChangePqOwnerMessageHash(
            address(wallet), currentPq, postPq
        );
        WOTSPlus.WinternitzElements memory rotateSig = _sign(currentPrivKey, rotateHash);

        vm.prank(BOB);
        wallet.changePqOwner(Codec.encodeChangePqOwner(postPq, rotateSig));

        (bytes32 s, bytes32 h) = wallet.pqOwner();
        assertEq(s, postPq.publicSeed);
        assertEq(h, postPq.publicKeyHash);

        // Step 4: ALICE locked out
        vm.prank(ALICE);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.changePqOwner(Codec.encodeChangePqOwner(postPq, rotateSig));
    }
}
