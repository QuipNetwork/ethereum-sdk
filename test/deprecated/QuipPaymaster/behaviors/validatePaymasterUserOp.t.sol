// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../../contracts/deprecated/interfaces/IQuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

contract QuipPaymaster_validatePaymasterUserOp is QuipPaymasterTest {
    /*─────────────────────────── helpers ───────────────────────────────*/

    /// @dev Signed userOp over the default WALLET envelope with a caller-supplied
    ///      current key and next verifier.
    function _signedUserOp(
        WOTSPlus.WinternitzAddress memory currentPub,
        bytes32 currentPriv,
        WOTSPlus.WinternitzAddress memory nextKey
    ) internal view returns (PackedUserOperation memory) {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        bytes memory paymasterAndData =
            _buildPaymasterAndData(WALLET, 0, "", validUntil, validAfter, currentPub, currentPriv, nextKey);
        return _mockUserOp(paymasterAndData);
    }

    /// @dev Signed userOp using the installed verifier and a fresh next key
    ///      derived from `"verifier-seed-1"`.
    function _defaultSignedUserOp()
        internal
        view
        returns (PackedUserOperation memory userOp, WOTSPlus.WinternitzAddress memory nextKey)
    {
        (nextKey,) = _generateKeyPair("verifier-seed-1");
        userOp = _signedUserOp(verifierPubkey, verifierPrivateKey, nextKey);
    }

    /// @dev UserOp whose paymasterAndData carries `nextKey` and a dummy signature
    ///      (not bound to the envelope). Used by checks that fire before WOTS+ verify.
    function _userOpWithUnsignedNextKey(WOTSPlus.WinternitzAddress memory nextKey)
        internal
        view
        returns (PackedUserOperation memory)
    {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        WOTSPlus.WinternitzElements memory dummySig = _sign(verifierPrivateKey, bytes32(0));
        bytes memory paymasterAndData = abi.encodePacked(
            address(paymaster),
            uint128(_DEFAULT_PM_VERIFICATION_GAS),
            uint128(_DEFAULT_PM_POSTOP_GAS),
            validUntil,
            validAfter,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            dummySig.elements
        );
        return _mockUserOp(paymasterAndData);
    }

    /// @dev Call `validatePaymasterUserOp` as the EntryPoint and assert it
    ///      emits `PaymasterValidationRejected` with `reason` and returns 1.
    function _assertValidateRejected(
        PackedUserOperation memory userOp,
        IQuipPaymaster.PaymasterValidationFailure reason
    ) internal {
        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.PaymasterValidationRejected(WALLET, reason);
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);
        assertEq(validationData, 1);
    }

    function test_validatePaymasterUserOp_validSignature() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("verifier-seed-1");

        bytes memory paymasterAndData =
            _buildPaymasterAndData(WALLET, 0, "", validUntil, validAfter, verifierPubkey, verifierPrivateKey, nextKey);
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ENTRY_POINT);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);

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
        (PackedUserOperation memory userOp, WOTSPlus.WinternitzAddress memory nextKey) = _defaultSignedUserOp();

        vm.prank(ENTRY_POINT);
        paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);

        // Verify key was rotated to nextKey
        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, nextKey.publicSeed);
        assertEq(v.publicKeyHash, nextKey.publicKeyHash);
    }

    function test_validatePaymasterUserOp_emitsPqVerifierRotated() public {
        (PackedUserOperation memory userOp, WOTSPlus.WinternitzAddress memory nextKey) = _defaultSignedUserOp();

        vm.prank(ENTRY_POINT);
        vm.expectEmit(true, false, false, true);
        emit IQuipPaymaster.PqVerifierRotated(WALLET, verifierPubkey, nextKey);
        paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);
    }

    function test_validatePaymasterUserOp_zeroValidUntil() public {
        // validUntil=0 means "no expiry" per ERC-4337
        uint48 validUntil = 0;
        uint48 validAfter = uint48(block.timestamp);

        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("verifier-seed-1");

        bytes memory paymasterAndData =
            _buildPaymasterAndData(WALLET, 0, "", validUntil, validAfter, verifierPubkey, verifierPrivateKey, nextKey);
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData);

        vm.prank(ENTRY_POINT);
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);

        assertEq(context, abi.encode(WALLET));
        assertEq(address(uint160(validationData)), address(0));
        assertEq(uint48(validationData >> 160), 0);
    }

    function test_validatePaymasterUserOp_wrongSigner() public {
        // Sign with a different (wrong) private key
        (WOTSPlus.WinternitzAddress memory wrongPubkey, bytes32 wrongPrivateKey) = _generateKeyPair("wrong-signer");
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("verifier-seed-1");

        _assertValidateRejected(
            _signedUserOp(wrongPubkey, wrongPrivateKey, nextKey),
            IQuipPaymaster.PaymasterValidationFailure.InvalidSignature
        );
    }

    function test_validatePaymasterUserOp_unregisteredWallet() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);

        address unregisteredWallet = makeAddr("unregistered");
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("verifier-seed-1");

        bytes memory paymasterAndData = _buildPaymasterAndData(
            unregisteredWallet, 0, "", validUntil, validAfter, verifierPubkey, verifierPrivateKey, nextKey
        );
        PackedUserOperation memory userOp = _mockUserOp(paymasterAndData, unregisteredWallet);

        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.PaymasterValidationRejected(
            unregisteredWallet, IQuipPaymaster.PaymasterValidationFailure.NoVerifierRegistered
        );
        (, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);

        assertEq(validationData, 1);
    }

    function test_validatePaymasterUserOp_differentCallData() public {
        (PackedUserOperation memory userOp,) = _defaultSignedUserOp();
        // Sign for empty callData but submit UserOp with different callData
        userOp.callData = hex"deadbeef";

        _assertValidateRejected(userOp, IQuipPaymaster.PaymasterValidationFailure.InvalidSignature);
    }

    function test_validatePaymasterUserOp_zeroNextKey() public {
        // Build paymasterAndData manually with zero nextVerifierKey
        WOTSPlus.WinternitzAddress memory zeroKey =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(0)});
        _assertValidateRejected(
            _userOpWithUnsignedNextKey(zeroKey), IQuipPaymaster.PaymasterValidationFailure.ZeroNextVerifier
        );
    }

    function test_validatePaymasterUserOp_keyReuse() public {
        // Try to set nextKey = currentKey (key reuse)
        _assertValidateRejected(
            _userOpWithUnsignedNextKey(verifierPubkey), IQuipPaymaster.PaymasterValidationFailure.NextEqualsCurrent
        );
    }

    function test_validatePaymasterUserOp_revertsWhen_notEntryPoint() public {
        (PackedUserOperation memory userOp,) = _defaultSignedUserOp();

        vm.prank(ALICE);
        vm.expectRevert(IQuipPaymaster.InvalidEntryPoint.selector);
        paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);
    }

    /// @dev Wrong-length `paymasterAndData` is rejected up-front with
    ///      `MalformedPayload` instead of a calldata-out-of-bounds panic.
    ///      Mirrors the strict-length guarantees the WOTS+ codec enforces;
    ///      a future change to the on-wire layout would otherwise either
    ///      silently truncate (overlong) or panic opaquely (short).
    function test_validatePaymasterUserOp_returnsOneWhen_paymasterAndDataTooShort() public {
        // 2271 bytes — one short of the 2272 protocol length.
        bytes memory shortData = new bytes(2271);
        // Encode the paymaster address into the first 20 bytes so the
        // EntryPoint-routing slice is at least syntactically valid.
        bytes20 pmAddr = bytes20(address(paymaster));
        for (uint256 i = 0; i < 20; i++) {
            shortData[i] = pmAddr[i];
        }
        PackedUserOperation memory userOp = _mockUserOp(shortData);

        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET, IQuipPaymaster.PaymasterValidationFailure.MalformedPayload
        );
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);
        assertEq(context.length, 0);
        assertEq(validationData, 1);
    }

    function test_validatePaymasterUserOp_returnsOneWhen_paymasterAndDataTooLong() public {
        uint48 validUntil = uint48(block.timestamp + 1 hours);
        uint48 validAfter = uint48(block.timestamp);
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("malformed-overlong-next");

        bytes memory base =
            _buildPaymasterAndData(WALLET, 0, "", validUntil, validAfter, verifierPubkey, verifierPrivateKey, nextKey);
        // Append an extra byte — a well-formed prefix won't save it from
        // the strict equality check.
        bytes memory overlong = abi.encodePacked(base, hex"00");
        PackedUserOperation memory userOp = _mockUserOp(overlong);

        vm.prank(ENTRY_POINT);
        vm.expectEmit(address(paymaster));
        emit IQuipPaymaster.PaymasterValidationRejected(
            WALLET, IQuipPaymaster.PaymasterValidationFailure.MalformedPayload
        );
        (bytes memory context, uint256 validationData) = paymaster.validatePaymasterUserOp(userOp, bytes32(0), 1 ether);
        assertEq(context.length, 0);
        assertEq(validationData, 1);

        // No rotation happened.
        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, verifierPubkey.publicSeed);
        assertEq(v.publicKeyHash, verifierPubkey.publicKeyHash);
    }
}
