// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../../contracts/deprecated/wots/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";

/// @title Ownership Lifecycle Scenario Test
/// @dev Full 2-step Solady ownership handover with PQ authentication:
///      ALICE operates → BOB requests handover → ALICE transfers + completes
///      → BOB is owner → BOB operates → ALICE is locked out.
contract WOTSPlusImplementation_ownershipLifecycle is WOTSPlusImplementationTest {
    WOTSPlus.WinternitzAddress internal currentPq;
    bytes32 internal currentPrivKey;

    struct OwnershipPayloadCtx {
        WOTSPlus.WinternitzAddress nextOwnership;
        WOTSPlus.WinternitzAddress newDisaster;
        WOTSPlus.WinternitzAddress[10] newTxn;
        bytes32[10] newTxnPrivs;
        WOTSPlus.WinternitzAddress[10] newRec;
        WOTSPlus.WinternitzAddress[10] newVer;
    }

    function _deriveOwnershipKeys(bytes32 seedPrefix) internal view returns (OwnershipPayloadCtx memory ctx) {
        (ctx.nextOwnership,) = _generateKeyPair(keccak256(abi.encodePacked(seedPrefix, "-new-ownership")));
        (ctx.newDisaster,) = _generateKeyPair(keccak256(abi.encodePacked(seedPrefix, "-new-disaster")));
        for (uint256 i = 0; i < 10; i++) {
            (ctx.newTxn[i], ctx.newTxnPrivs[i]) = _generateKeyPair(keccak256(abi.encodePacked(seedPrefix, "-txn", i)));
        }
        for (uint256 i = 0; i < 10; i++) {
            (ctx.newRec[i],) = _generateKeyPair(keccak256(abi.encodePacked(seedPrefix, "-rec", i)));
        }
        for (uint256 i = 0; i < 10; i++) {
            (ctx.newVer[i],) = _generateKeyPair(keccak256(abi.encodePacked(seedPrefix, "-ver", i)));
        }
    }

    function _encodeOwnershipPayload(
        OwnershipPayloadCtx memory ctx,
        address newOwner,
        WOTSPlus.WinternitzAddress memory curOwnership,
        bytes32 curOwnershipPriv
    ) internal view returns (bytes memory) {
        bytes32 keysHash = keccak256(abi.encode(ctx.newDisaster, ctx.newTxn, ctx.newRec, ctx.newVer));
        bytes32 msgHash =
            _buildTransferOwnershipMessageHash(address(wallet), curOwnership, ctx.nextOwnership, newOwner, keysHash);
        WOTSPlus.WinternitzElements memory sig = _sign(curOwnershipPriv, msgHash);
        return Codec.encodeOwnershipTransfer(
            curOwnership, ctx.nextOwnership, sig, newOwner, ctx.newDisaster, ctx.newTxn, ctx.newRec, ctx.newVer
        );
    }

    /// @dev Full ownership lifecycle: operate → transfer → new owner operates.
    function test_simulation_ownershipLifecycle() public {
        currentPq = alicePubkey;
        currentPrivKey = alicePrivateKey;

        // Step 1: ALICE operates the wallet normally
        {
            (WOTSPlus.WinternitzAddress memory nextPq, bytes32 nextPriv) = _generateKeyPair("pre-transfer-key");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(address(wallet), currentPq, nextPq, BOB, 0.05 ether, "", fee);
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            vm.prank(ALICE);
            wallet.execute(Codec.encodeExecute(currentPq, nextPq, sig, BOB, 0.05 ether, ""));

            currentPq = nextPq;
            currentPrivKey = nextPriv;
        }

        // Step 2: ALICE directly transfers ownership to BOB via transferOwnership(bytes).
        //   Full re-init semantics — the new owner gets a fresh batch of PQ keys.
        OwnershipPayloadCtx memory directCtx = _deriveOwnershipKeys("lifecycle-direct");
        {
            bytes memory payload = _encodeOwnershipPayload(directCtx, BOB, ownershipPubkey, ownershipPrivateKey);
            vm.prank(ALICE);
            wallet.transferOwnership(payload);
        }

        // After transferOwnership, owner is BOB (Solady direct transfer)
        assertEq(wallet.owner(), BOB);

        // Step 4: BOB can now operate the wallet using one of the freshly installed txn keys.
        {
            currentPq = directCtx.newTxn[0];
            currentPrivKey = directCtx.newTxnPrivs[0];
            (WOTSPlus.WinternitzAddress memory nextPq,) = _generateKeyPair("bob-exec-key");
            uint256 fee = wallet.getExecuteFee();
            bytes32 msgHash = _buildExecuteMessageHash(address(wallet), currentPq, nextPq, BOB, 0.01 ether, "", fee);
            WOTSPlus.WinternitzElements memory sig = _sign(currentPrivKey, msgHash);

            uint256 bobBal = BOB.balance;
            vm.prank(BOB);
            wallet.execute(Codec.encodeExecute(currentPq, nextPq, sig, BOB, 0.01 ether, ""));
            assertEq(BOB.balance, bobBal + 0.01 ether);
        }

        // Step 5: ALICE is locked out — cannot call owner-gated functions
        {
            (WOTSPlus.WinternitzAddress memory dummyPq,) = _generateKeyPair("alice-locked-out");
            // Use a dummy signature; we expect Unauthorized before sig check
            WOTSPlus.WinternitzElements memory dummySig = _sign(currentPrivKey, bytes32(0));

            vm.prank(ALICE);
            vm.expectRevert(SoladyOwnable.Unauthorized.selector);
            wallet.execute(Codec.encodeExecute(alicePubkey, dummyPq, dummySig, BOB, 0, ""));
        }
    }
}
