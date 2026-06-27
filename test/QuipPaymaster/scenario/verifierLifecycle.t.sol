// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title QuipPaymaster Verifier Lifecycle Scenario
/// @dev End-to-end simulation of the owner's verifier-management path
///      interleaved with EntryPoint-driven rotations: register → EntryPoint
///      rotates → owner force-replaces mid-chain → old (rotated-out) sigs fail
///      → owner removes the verifier → subsequent UserOps fail with the
///      "no verifier" branch → owner re-registers → chain resumes.
contract QuipPaymaster_verifierLifecycle is QuipPaymasterTest {
    function _validate(bytes memory data, address sender_) internal {
        vm.prank(ENTRY_POINT);
        paymaster.validatePaymasterUserOp(
            _mockUserOp(data, sender_),
            bytes32(0),
            0
        );
    }

    function _validateExpectingFailure(
        bytes memory data,
        address sender_
    ) internal returns (uint256 validationData) {
        vm.prank(ENTRY_POINT);
        (, validationData) = paymaster.validatePaymasterUserOp(
            _mockUserOp(data, sender_),
            bytes32(0),
            0
        );
    }

    function test_simulation_verifierLifecycle() public {
        // ── Step 1: EntryPoint-driven rotation from the initial verifier ──
        (
            WOTSPlus.WinternitzAddress memory nextV,
            bytes32 nextVPriv
        ) = _generateKeyPair("vlc-next-1");
        bytes memory data1 = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            uint48(block.timestamp + 1 hours),
            uint48(0),
            verifierPubkey,
            verifierPrivateKey,
            nextV
        );
        _validate(data1, WALLET);

        // Verifier rotated.
        assertEq(
            paymaster.getPqVerifier(WALLET).publicSeed,
            nextV.publicSeed
        );

        // ── Step 2: Owner force-replaces the current verifier mid-chain ──
        //   This is the administrative override — e.g. signer key retired,
        //   operator rotating the backend — and bypasses the WOTS+ chain by
        //   design. The old `nextV` is discarded; a new chain root `forcedV`
        //   takes over.
        (
            WOTSPlus.WinternitzAddress memory forcedV,
            bytes32 forcedVPriv
        ) = _generateKeyPair("vlc-forced");
        vm.prank(ADMIN);
        paymaster.setPqVerifier(WALLET, forcedV);
        assertEq(
            paymaster.getPqVerifier(WALLET).publicSeed,
            forcedV.publicSeed
        );

        // ── Step 3: A UserOp signed under the rotated-out `nextV` must fail ──
        //   The digest's `currentVerifier` fields now reflect `forcedV`, so any
        //   sig produced under `nextV` can no longer reconstruct the digest.
        {
            (
                WOTSPlus.WinternitzAddress memory stale,

            ) = _generateKeyPair("vlc-stale-next");
            bytes memory staleData = _buildPaymasterAndData(
                WALLET,
                0,
                "",
                uint48(block.timestamp + 1 hours),
                uint48(0),
                nextV, // rotated out by step 2
                nextVPriv,
                stale
            );
            uint256 vdStale = _validateExpectingFailure(staleData, WALLET);
            // Authorizer = 1 = SIG_VALIDATION_FAILED.
            assertEq(uint160(vdStale), 1);

            // No rotation happened — forcedV still installed.
            assertEq(
                paymaster.getPqVerifier(WALLET).publicSeed,
                forcedV.publicSeed
            );
        }

        // ── Step 4: A valid UserOp under `forcedV` rotates the chain again ──
        (
            WOTSPlus.WinternitzAddress memory afterForced,

        ) = _generateKeyPair("vlc-after-forced");
        {
            // Nonce must match `_mockUserOp`'s hardcoded nonce=0 so the paymaster
            // reconstructs the same opCommitment we signed over.
            bytes memory data2 = _buildPaymasterAndData(
                WALLET,
                0,
                "",
                uint48(block.timestamp + 1 hours),
                uint48(0),
                forcedV,
                forcedVPriv,
                afterForced
            );
            _validate(data2, WALLET);
            assertEq(
                paymaster.getPqVerifier(WALLET).publicSeed,
                afterForced.publicSeed
            );
        }

        // ── Step 5: Owner removes the verifier entirely ────────────────
        vm.prank(ADMIN);
        paymaster.removePqVerifier(WALLET);

        // Storage cleared.
        assertEq(paymaster.getPqVerifier(WALLET).publicSeed, bytes32(0));
        assertEq(paymaster.getPqVerifier(WALLET).publicKeyHash, bytes32(0));

        // ── Step 6: Further UserOps are rejected with SIG_VALIDATION_FAILED ──
        //   This time the failure comes from the "no verifier registered"
        //   branch, not the sig-verify branch.
        {
            (
                WOTSPlus.WinternitzAddress memory orphanNext,

            ) = _generateKeyPair("vlc-orphan-next");
            bytes memory orphanData = _buildPaymasterAndData(
                WALLET,
                0,
                "",
                uint48(block.timestamp + 1 hours),
                uint48(0),
                forcedV,
                forcedVPriv,
                orphanNext
            );
            uint256 vdOrphan = _validateExpectingFailure(orphanData, WALLET);
            assertEq(uint160(vdOrphan), 1);
        }

        // ── Step 7: Double-remove is rejected ──────────────────────────
        vm.prank(ADMIN);
        vm.expectRevert(IQuipPaymaster.PqVerifierNotRegistered.selector);
        paymaster.removePqVerifier(WALLET);

        // ── Step 8: Owner re-registers; the chain resumes under a fresh root ──
        (
            WOTSPlus.WinternitzAddress memory reregPub,
            bytes32 reregPriv
        ) = _generateKeyPair("vlc-rereg");
        vm.prank(ADMIN);
        paymaster.setPqVerifier(WALLET, reregPub);
        assertEq(
            paymaster.getPqVerifier(WALLET).publicSeed,
            reregPub.publicSeed
        );

        // A UserOp under the freshly registered key validates and rotates.
        (
            WOTSPlus.WinternitzAddress memory postRereg,

        ) = _generateKeyPair("vlc-post-rereg");
        bytes memory reregData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            uint48(block.timestamp + 1 hours),
            uint48(0),
            reregPub,
            reregPriv,
            postRereg
        );
        _validate(reregData, WALLET);
        assertEq(
            paymaster.getPqVerifier(WALLET).publicSeed,
            postRereg.publicSeed
        );
    }
}
