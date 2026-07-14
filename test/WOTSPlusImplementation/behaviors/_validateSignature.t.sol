// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

/// @dev Behaviour tests for `_validateSignature(PackedUserOperation, userOpHash) → uint256`.
///      Returns 0 on valid signature (and commits the key rotation); returns 1
///      on every validation failure. Never reverts.
contract WOTSPlusImplementation__validateSignature is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    WOTSPlus.WinternitzAddress internal currentKey;
    bytes32 internal currentPriv;

    function setUp() public override {
        super.setUp();
        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (currentKey, currentPriv) = _generateKeyPair("h-vs-current");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(currentPriv, 10);
        bytes memory payload = _encodeInitPayload(currentKey, rKeys);

        vm.prank(ALICE);
        address proxyAddr =
            factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("h-vs-vault"), payable(ALICE), payload);
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    function _makeUserOp(bytes memory sig) internal view returns (ERC4337.PackedUserOperation memory op) {
        op = ERC4337.PackedUserOperation({
            sender: address(harnessProxy),
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: sig
        });
    }

    function _digestForUserOpHash(
        WOTSPlus.WinternitzAddress memory current,
        WOTSPlus.WinternitzAddress memory next,
        bytes32 userOpHash
    ) internal view returns (bytes32) {
        return Codec.erc4337ExecuteDigest(
            address(harnessProxy),
            block.chainid,
            current.publicSeed,
            current.publicKeyHash,
            next.publicSeed,
            next.publicKeyHash,
            userOpHash,
            harnessProxy.getExecuteFee()
        );
    }

    function test_exposed_validateSignature_happyPath_returnsZeroAndRotates() public {
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("h-vs-next");

        bytes32 userOpHash = keccak256("user-op-hash-1");
        bytes32 digest = _digestForUserOpHash(currentKey, nextKey, userOpHash);
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);
        bytes memory sigBytes = Codec.encodeUserOpSignature(currentKey, nextKey, sig);

        ERC4337.PackedUserOperation memory op = _makeUserOp(sigBytes);
        // Happy path emits no UserOpValidationRejected event; recordLogs lets us
        // scan post-call to confirm absence rather than just trust expectEmit.
        vm.recordLogs();
        uint256 rv = harnessProxy.exposed_validateSignature(op, userOpHash);
        assertEq(rv, 0);
        bytes32 rejectedSig = IWOTSPlusImplementation.UserOpValidationRejected.selector;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            assertTrue(logs[i].topics.length == 0 || logs[i].topics[0] != rejectedSig);
        }

        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, currentKey));
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, nextKey));
    }

    function test_exposed_validateSignature_returnsOneWhen_nextKeyZeroSeed() public {
        WOTSPlus.WinternitzAddress memory badNext =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(0), publicKeyHash: bytes32(uint256(1))});
        bytes32 userOpHash = keccak256("uo-2");
        WOTSPlus.WinternitzElements memory sig; // zero-filled is fine — short-circuits
        bytes memory sigBytes = Codec.encodeUserOpSignature(currentKey, badNext, sig);

        ERC4337.PackedUserOperation memory op = _makeUserOp(sigBytes);
        vm.expectEmit(address(harnessProxy));
        emit IWOTSPlusImplementation.UserOpValidationRejected(IWOTSPlusImplementation.UserOpValidationFailure
            .ZeroNextKey);
        uint256 rv = harnessProxy.exposed_validateSignature(op, userOpHash);
        assertEq(rv, 1);
    }

    function test_exposed_validateSignature_returnsOneWhen_nextKeyZeroHash() public {
        WOTSPlus.WinternitzAddress memory badNext =
            WOTSPlus.WinternitzAddress({publicSeed: bytes32(uint256(1)), publicKeyHash: bytes32(0)});
        bytes32 userOpHash = keccak256("uo-3");
        WOTSPlus.WinternitzElements memory sig;
        bytes memory sigBytes = Codec.encodeUserOpSignature(currentKey, badNext, sig);

        ERC4337.PackedUserOperation memory op = _makeUserOp(sigBytes);
        vm.expectEmit(address(harnessProxy));
        emit IWOTSPlusImplementation.UserOpValidationRejected(IWOTSPlusImplementation.UserOpValidationFailure
            .ZeroNextKey);
        uint256 rv = harnessProxy.exposed_validateSignature(op, userOpHash);
        assertEq(rv, 1);
    }

    function test_exposed_validateSignature_returnsOneWhen_currentKeyAbsent() public {
        (WOTSPlus.WinternitzAddress memory stray, bytes32 strayPriv) = _generateKeyPair("h-vs-stray");
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("h-vs-next-b");

        bytes32 userOpHash = keccak256("uo-4");
        bytes32 digest = _digestForUserOpHash(stray, nextKey, userOpHash);
        WOTSPlus.WinternitzElements memory sig = _sign(strayPriv, digest);
        bytes memory sigBytes = Codec.encodeUserOpSignature(stray, nextKey, sig);

        ERC4337.PackedUserOperation memory op = _makeUserOp(sigBytes);
        vm.expectEmit(address(harnessProxy));
        emit IWOTSPlusImplementation.UserOpValidationRejected(IWOTSPlusImplementation.UserOpValidationFailure
            .StaleCurrentKey);
        uint256 rv = harnessProxy.exposed_validateSignature(op, userOpHash);
        assertEq(rv, 1);
    }

    function test_exposed_validateSignature_returnsOneWhen_nextKeyAlreadyPresent() public {
        // Pick an existing txn key as `next` so `contains(nextKey)` fires.
        WOTSPlus.WinternitzAddress memory nextPresent = harnessProxy.keyAt(Codec.KeyType.Transaction, 1);

        bytes32 userOpHash = keccak256("uo-5");
        bytes32 digest = _digestForUserOpHash(currentKey, nextPresent, userOpHash);
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);
        bytes memory sigBytes = Codec.encodeUserOpSignature(currentKey, nextPresent, sig);

        ERC4337.PackedUserOperation memory op = _makeUserOp(sigBytes);
        vm.expectEmit(address(harnessProxy));
        emit IWOTSPlusImplementation.UserOpValidationRejected(IWOTSPlusImplementation.UserOpValidationFailure
            .NextKeyAlreadyInUse);
        uint256 rv = harnessProxy.exposed_validateSignature(op, userOpHash);
        assertEq(rv, 1);
    }

    function test_exposed_validateSignature_returnsOneWhen_signatureInvalid() public {
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("h-vs-next-c");

        bytes32 userOpHash = keccak256("uo-6");
        // Sign a different digest than the one that will be derived.
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, keccak256("different"));
        bytes memory sigBytes = Codec.encodeUserOpSignature(currentKey, nextKey, sig);

        ERC4337.PackedUserOperation memory op = _makeUserOp(sigBytes);
        vm.expectEmit(address(harnessProxy));
        emit IWOTSPlusImplementation.UserOpValidationRejected(IWOTSPlusImplementation.UserOpValidationFailure
            .InvalidSignature);
        uint256 rv = harnessProxy.exposed_validateSignature(op, userOpHash);
        assertEq(rv, 1);

        // Failure must NOT rotate keys.
        assertTrue(harnessProxy.isKey(Codec.KeyType.Transaction, currentKey));
        assertFalse(harnessProxy.isKey(Codec.KeyType.Transaction, nextKey));
    }
}
