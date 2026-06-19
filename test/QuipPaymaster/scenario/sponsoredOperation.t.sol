// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title QuipPaymaster Sponsored Operation Scenario Test
/// @dev Scenario: paymaster validates a UserOp and rotates the verifier key.
///      Covers single validation, sequential validations, and expired operations.
contract QuipPaymaster_sponsoredOperation is QuipPaymasterTest {
    /// @dev Verifier key rotates on each validated UserOp
    function test_simulation_verifierRotatesOnValidation() public {
        // Generate next verifier key
        (WOTSPlus.WinternitzAddress memory nextVerifier,) = _generateKeyPair("next-verifier-1");

        // Build paymasterAndData with valid signature
        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            uint48(block.timestamp + 1 hours),
            uint48(0),
            verifierPubkey,
            verifierPrivateKey,
            nextVerifier
        );

        // Call validatePaymasterUserOp as EntryPoint
        vm.prank(ENTRY_POINT);
        (bytes memory context, uint256 validationData) =
            paymaster.validatePaymasterUserOp(_mockUserOp(paymasterAndData), bytes32(0), 0);

        // Validation should succeed (authorizer address = 0 means success)
        assertEq(uint160(validationData), 0);

        // Context carries the sponsored wallet so postOp can attribute spend.
        assertEq(context, abi.encode(WALLET));

        // Verifier should have rotated
        WOTSPlus.WinternitzAddress memory stored = paymaster.getPqVerifier(WALLET);
        assertEq(stored.publicSeed, nextVerifier.publicSeed);
        assertEq(stored.publicKeyHash, nextVerifier.publicKeyHash);
    }

    /// @dev Sequential validations each rotate the verifier key
    function test_simulation_sequentialValidationsRotateKeys() public {
        // First validation: rotate from initial to next1
        (WOTSPlus.WinternitzAddress memory next1, bytes32 next1PrivKey) = _generateKeyPair("seq-verifier-1");

        bytes memory paymasterAndData1 = _buildPaymasterAndData(
            WALLET, 0, "", uint48(block.timestamp + 1 hours), uint48(0), verifierPubkey, verifierPrivateKey, next1
        );

        vm.prank(ENTRY_POINT);
        paymaster.validatePaymasterUserOp(_mockUserOp(paymasterAndData1), bytes32(0), 0);

        // Verify first rotation
        WOTSPlus.WinternitzAddress memory stored1 = paymaster.getPqVerifier(WALLET);
        assertEq(stored1.publicSeed, next1.publicSeed);
        assertEq(stored1.publicKeyHash, next1.publicKeyHash);

        // Second validation: rotate from next1 to next2
        (WOTSPlus.WinternitzAddress memory next2,) = _generateKeyPair("seq-verifier-2");

        bytes memory paymasterAndData2 = _buildPaymasterAndData(
            WALLET, 0, "", uint48(block.timestamp + 1 hours), uint48(0), next1, next1PrivKey, next2
        );

        vm.prank(ENTRY_POINT);
        paymaster.validatePaymasterUserOp(_mockUserOp(paymasterAndData2), bytes32(0), 0);

        // Verify second rotation
        WOTSPlus.WinternitzAddress memory stored2 = paymaster.getPqVerifier(WALLET);
        assertEq(stored2.publicSeed, next2.publicSeed);
        assertEq(stored2.publicKeyHash, next2.publicKeyHash);

        // Original key is no longer the verifier
        assertTrue(stored2.publicSeed != verifierPubkey.publicSeed);
    }

    /// @dev Expired validUntil returns SIG_VALIDATION_FAILED via packed validationData.
    ///      The paymaster still rotates the key (signature was valid), but the EntryPoint
    ///      will reject the UserOp based on the expiry window.
    function test_simulation_expiredOpStillRotatesKey() public {
        (WOTSPlus.WinternitzAddress memory nextVerifier,) = _generateKeyPair("expired-verifier");

        // Set validUntil to a past timestamp
        uint48 expiredUntil = uint48(block.timestamp - 1);

        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET, 0, "", expiredUntil, uint48(0), verifierPubkey, verifierPrivateKey, nextVerifier
        );

        vm.prank(ENTRY_POINT);
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(_mockUserOp(paymasterAndData), bytes32(0), 0);

        // Authorizer is 0 (signature valid) but validUntil is past, so EntryPoint rejects
        uint160 authorizer = uint160(validationData);
        assertEq(authorizer, 0);

        // validUntil is packed at bits [160:208)
        uint48 returnedValidUntil = uint48(validationData >> 160);
        assertEq(returnedValidUntil, expiredUntil);

        // Key still rotated because the WOTS+ signature was valid
        WOTSPlus.WinternitzAddress memory stored = paymaster.getPqVerifier(WALLET);
        assertEq(stored.publicSeed, nextVerifier.publicSeed);
        assertEq(stored.publicKeyHash, nextVerifier.publicKeyHash);
    }

    /// @dev Future validAfter returns success but marks the op as not-yet-valid.
    ///      Like the expired case, the WOTS+ signature is valid so the key must
    ///      still rotate — the window check is the EntryPoint's concern, not the
    ///      paymaster's.
    function test_simulation_futureValidAfter() public {
        (WOTSPlus.WinternitzAddress memory nextVerifier,) = _generateKeyPair("future-verifier");

        uint48 futureAfter = uint48(block.timestamp + 1 hours);

        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            uint48(block.timestamp + 2 hours),
            futureAfter,
            verifierPubkey,
            verifierPrivateKey,
            nextVerifier
        );

        vm.prank(ENTRY_POINT);
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(_mockUserOp(paymasterAndData), bytes32(0), 0);

        // Authorizer is 0 (valid signature)
        uint160 authorizer = uint160(validationData);
        assertEq(authorizer, 0);

        // validAfter is packed at bits [208:256)
        uint48 returnedValidAfter = uint48(validationData >> 208);
        assertEq(returnedValidAfter, futureAfter);

        // Key rotated despite the op being not-yet-valid — WOTS+ is one-time-use.
        WOTSPlus.WinternitzAddress memory stored = paymaster.getPqVerifier(WALLET);
        assertEq(stored.publicSeed, nextVerifier.publicSeed);
        assertEq(stored.publicKeyHash, nextVerifier.publicKeyHash);
    }

    /// @dev Multi-wallet sponsorship: paymaster tracks independent verifier chains per wallet.
    function test_simulation_multiWalletIndependentRotation() public {
        address WALLET_B = address(0xbeef);

        // Register a separate verifier for WALLET_B
        (WOTSPlus.WinternitzAddress memory verifierB, bytes32 verifierBPrivKey) =
            _generateKeyPair("wallet-b-verifier-0");
        vm.prank(ADMIN);
        paymaster.setPqVerifier(WALLET_B, verifierB);

        // Rotate WALLET's verifier
        (WOTSPlus.WinternitzAddress memory nextA,) = _generateKeyPair("wallet-a-next");
        bytes memory dataA = _buildPaymasterAndData(
            WALLET, 0, "", uint48(block.timestamp + 1 hours), uint48(0), verifierPubkey, verifierPrivateKey, nextA
        );

        vm.prank(ENTRY_POINT);
        paymaster.validatePaymasterUserOp(_mockUserOp(dataA), bytes32(0), 0);

        // Rotate WALLET_B's verifier
        (WOTSPlus.WinternitzAddress memory nextB,) = _generateKeyPair("wallet-b-next");
        bytes memory dataB = _buildPaymasterAndData(
            WALLET_B, 0, "", uint48(block.timestamp + 1 hours), uint48(0), verifierB, verifierBPrivKey, nextB
        );

        vm.prank(ENTRY_POINT);
        paymaster.validatePaymasterUserOp(_mockUserOp(dataB, WALLET_B), bytes32(0), 0);

        // Both wallets have independent verifier state
        WOTSPlus.WinternitzAddress memory storedA = paymaster.getPqVerifier(WALLET);
        assertEq(storedA.publicSeed, nextA.publicSeed);

        WOTSPlus.WinternitzAddress memory storedB = paymaster.getPqVerifier(WALLET_B);
        assertEq(storedB.publicSeed, nextB.publicSeed);

        // Original keys differ from current
        assertTrue(storedA.publicSeed != verifierPubkey.publicSeed);
        assertTrue(storedB.publicSeed != verifierB.publicSeed);
    }
}
