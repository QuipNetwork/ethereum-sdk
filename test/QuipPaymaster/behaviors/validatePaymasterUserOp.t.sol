// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

contract QuipPaymaster_validatePaymasterUserOp is QuipPaymasterTest {
    function test_validatePaymasterUserOp_validSignature() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        (WOTSPlus.WinternitzAddress memory nextKey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            validUntil,
            validAfter,
            verifierPubkey,
            verifierPrivateKey,
            nextKey
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ENTRY_POINT);
        (bytes memory context, uint256 validationData) = paymaster
            .validatePaymasterUserOp(userOp, bytes32(0), 1 ether);

        // Context carries the sponsored wallet so postOp can attribute spend.
        assertEq(context, abi.encode(WALLET));

        // Unpack validationData: authorizer=0 (success), validUntil, validAfter
        address authorizer = address(uint160(validationData));
        uint48 returnedValidUntil = uint48(validationData >> 160);
        uint48 returnedValidAfter = uint48(validationData >> 208);

        assertEq(authorizer, address(0));
        assertEq(returnedValidUntil, validUntil);
        assertEq(returnedValidAfter, validAfter);
    }

    function test_validatePaymasterUserOp_rotatesVerifierKey() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        (WOTSPlus.WinternitzAddress memory nextKey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            validUntil,
            validAfter,
            verifierPubkey,
            verifierPrivateKey,
            nextKey
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ENTRY_POINT);
        paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);

        // Verify key was rotated to nextKey
        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, nextKey.publicSeed);
        assertEq(v.publicKeyHash, nextKey.publicKeyHash);
    }

    function test_validatePaymasterUserOp_emitsPqVerifierRotated() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        (WOTSPlus.WinternitzAddress memory nextKey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            validUntil,
            validAfter,
            verifierPubkey,
            verifierPrivateKey,
            nextKey
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ENTRY_POINT);
        vm.expectEmit(true, false, false, true);
        emit IQuipPaymaster.PqVerifierRotated(WALLET, verifierPubkey, nextKey);
        paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);
    }

    function test_validatePaymasterUserOp_zeroValidUntil() public {
        // validUntil=0 means "no expiry" per ERC-4337
        uint48 validUntil = 0;
        uint48 validAfter = uint48(block.timestamp);

        (WOTSPlus.WinternitzAddress memory nextKey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            validUntil,
            validAfter,
            verifierPubkey,
            verifierPrivateKey,
            nextKey
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ENTRY_POINT);
        (bytes memory context, uint256 validationData) = paymaster
            .validatePaymasterUserOp(userOp, bytes32(0), 1 ether);

        assertEq(context, abi.encode(WALLET));
        assertEq(address(uint160(validationData)), address(0));
        assertEq(uint48(validationData >> 160), 0);
    }

    function test_validatePaymasterUserOp_wrongSigner() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        // Sign with a different (wrong) private key
        (
            WOTSPlus.WinternitzAddress memory wrongPubkey,
            bytes32 wrongPrivateKey
        ) = _generateKeyPair("wrong-signer");
        (WOTSPlus.WinternitzAddress memory nextKey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            validUntil,
            validAfter,
            wrongPubkey,
            wrongPrivateKey,
            nextKey
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET,
            IQuipPaymaster.PaymasterValidationFailure.InvalidSignature
        );
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            bytes32(0),
            1 ether
        );

        // Should return SIG_VALIDATION_FAILED (1)
        assertEq(validationData, 1);
    }

    function test_validatePaymasterUserOp_unregisteredWallet() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        address unregisteredWallet = makeAddr("unregistered");
        (WOTSPlus.WinternitzAddress memory nextKey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        bytes memory paymasterAndData = _buildPaymasterAndData(
            unregisteredWallet,
            0,
            "",
            validUntil,
            validAfter,
            verifierPubkey,
            verifierPrivateKey,
            nextKey
        );
        PackedUserOperation memory userOp = _mockUserOp(
            paymasterAndData,
            unregisteredWallet
        );

        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.PaymasterValidationRejected(
            unregisteredWallet,
            IQuipPaymaster.PaymasterValidationFailure.NoVerifierRegistered
        );
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            bytes32(0),
            1 ether
        );

        assertEq(validationData, 1);
    }

    function test_validatePaymasterUserOp_differentCallData() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        (WOTSPlus.WinternitzAddress memory nextKey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        // Sign for empty callData but submit UserOp with different callData
        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            validUntil,
            validAfter,
            verifierPubkey,
            verifierPrivateKey,
            nextKey
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);
        userOp.callData = hex"deadbeef";

        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET,
            IQuipPaymaster.PaymasterValidationFailure.InvalidSignature
        );
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            bytes32(0),
            1 ether
        );

        // Signature was for empty callData but UserOp has different callData, so validation fails
        assertEq(validationData, 1);
    }

    function test_validatePaymasterUserOp_zeroNextKey() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        // Build paymasterAndData manually with zero nextVerifierKey
        WOTSPlus.WinternitzAddress memory zeroKey = WOTSPlus.WinternitzAddress({
            publicSeed: bytes32(0),
            publicKeyHash: bytes32(0)
        });
        WOTSPlus.WinternitzElements memory dummySig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );

        bytes memory paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100_000),
            uint128(50_000),
            validUntil,
            validAfter,
            zeroKey.publicSeed,
            zeroKey.publicKeyHash,
            dummySig.elements
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET,
            IQuipPaymaster.PaymasterValidationFailure.ZeroNextVerifier
        );
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            bytes32(0),
            1 ether
        );

        assertEq(validationData, 1);
    }

    function test_validatePaymasterUserOp_keyReuse() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        // Try to set nextKey = currentKey (key reuse)
        WOTSPlus.WinternitzElements memory dummySig = _sign(
            verifierPrivateKey,
            bytes32(0)
        );

        bytes memory paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(100_000),
            uint128(50_000),
            validUntil,
            validAfter,
            verifierPubkey.publicSeed,
            verifierPubkey.publicKeyHash,
            dummySig.elements
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET,
            IQuipPaymaster.PaymasterValidationFailure.NextEqualsCurrent
        );
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(
            userOp,
            bytes32(0),
            1 ether
        );

        assertEq(validationData, 1);
    }

    function test_validatePaymasterUserOp_revertsWhen_notEntryPoint() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        (WOTSPlus.WinternitzAddress memory nextKey, ) = _generateKeyPair(
            "verifier-seed-1"
        );

        bytes memory paymasterAndData = _buildPaymasterAndData(
            WALLET,
            0,
            "",
            validUntil,
            validAfter,
            verifierPubkey,
            verifierPrivateKey,
            nextKey
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ALICE);
        vm.expectRevert(IQuipPaymaster.InvalidEntryPoint.selector);
        paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);
    }
}
