// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_completeOwnershipHandover is QuipWalletTest {
    event OwnershipTransferred(
        address indexed oldOwner,
        address indexed newOwner
    );

    WOTSPlus.WinternitzAddress internal newOwnershipKey;
    WOTSPlus.WinternitzAddress internal newDisasterKey;
    WOTSPlus.WinternitzAddress[5] internal freshTxnKeys;
    WOTSPlus.WinternitzAddress[10] internal freshRecoveryKeys;

    function setUp() public override {
        super.setUp();
        (newOwnershipKey, ) = _generateKeyPair("handover-new-ownership");
        (newDisasterKey, ) = _generateKeyPair("handover-new-disaster");
        for (uint256 i = 0; i < 5; i++) {
            (freshTxnKeys[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked("handover-txn", i))
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            (freshRecoveryKeys[i], ) = _generateKeyPair(
                keccak256(abi.encodePacked("handover-rec", i))
            );
        }
    }

    function _keysHash() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(newDisasterKey, freshTxnKeys, freshRecoveryKeys)
            );
    }

    function _buildPayload(
        WOTSPlus.WinternitzAddress memory curOwnership,
        bytes32 curOwnershipPriv,
        WOTSPlus.WinternitzAddress memory nextOwnership,
        address pendingOwner,
        WOTSPlus.WinternitzAddress memory disasterKey
    ) internal view returns (bytes memory) {
        bytes32 keysHash = keccak256(
            abi.encode(disasterKey, freshTxnKeys, freshRecoveryKeys)
        );
        bytes32 msgHash = _buildCompleteOwnershipHandoverMessageHash(
            address(wallet),
            curOwnership,
            nextOwnership,
            pendingOwner,
            keysHash
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            curOwnershipPriv,
            msgHash
        );
        return
            Codec.encodeOwnershipTransfer(
                curOwnership,
                nextOwnership,
                sig,
                pendingOwner,
                disasterKey,
                freshTxnKeys,
                freshRecoveryKeys
            );
    }

    function _requestHandover(address pendingOwner) internal {
        vm.prank(pendingOwner);
        wallet.requestOwnershipHandover();
    }

    // ── Happy paths ──────────────────────────────────────────────────

    function test_completeOwnershipHandover_completesHandover() public {
        _requestHandover(BOB);
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(payload);

        assertEq(wallet.owner(), BOB);
    }

    function test_completeOwnershipHandover_replacesTxnAndRecoveryKeys()
        public
    {
        _requestHandover(BOB);
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(payload);

        assertEq(wallet.keyCount(Codec.KeyType.Transaction), 5);
        assertEq(wallet.keyCount(Codec.KeyType.Recovery), 10);
        for (uint256 i = 0; i < 5; i++) {
            assertTrue(
                wallet.isKey(Codec.KeyType.Transaction, freshTxnKeys[i])
            );
        }
        for (uint256 i = 0; i < 10; i++) {
            assertTrue(
                wallet.isKey(Codec.KeyType.Recovery, freshRecoveryKeys[i])
            );
        }
    }

    function test_completeOwnershipHandover_clearsVerificationKeys() public {
        (
            WOTSPlus.WinternitzAddress[] memory verKeys,

        ) = _seedVerificationKeys(3);
        assertEq(wallet.keyCount(Codec.KeyType.Verification), 3);

        _requestHandover(BOB);
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );
        vm.prank(ALICE);
        wallet.completeOwnershipHandover(payload);

        assertEq(wallet.keyCount(Codec.KeyType.Verification), 0);
        for (uint256 i = 0; i < verKeys.length; i++) {
            assertFalse(wallet.isKey(Codec.KeyType.Verification, verKeys[i]));
        }
    }

    function test_completeOwnershipHandover_emitsOwnershipTransferred() public {
        _requestHandover(BOB);
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.expectEmit(true, true, false, false, address(wallet));
        emit OwnershipTransferred(ALICE, BOB);

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_emitsOwnershipReinitialized()
        public
    {
        _requestHandover(BOB);
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.expectEmit(false, false, false, true, address(wallet));
        emit IQuipWallet.OwnershipReinitialized(
            ownershipPubkey,
            newOwnershipKey,
            BOB,
            newDisasterKey,
            keccak256(abi.encode(freshTxnKeys)),
            keccak256(abi.encode(freshRecoveryKeys))
        );

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(payload);
    }

    // ── Revert paths ─────────────────────────────────────────────────

    function test_completeOwnershipHandover_revertsWhen_classicalCalled()
        public
    {
        vm.prank(ALICE);
        vm.expectRevert(
            IQuipWallet.ClassicalCompleteOwnershipHandoverDisabled.selector
        );
        wallet.completeOwnershipHandover(BOB);
    }

    function test_completeOwnershipHandover_revertsWhen_classicalCalledByNonOwner()
        public
    {
        vm.prank(BOB);
        vm.expectRevert(
            IQuipWallet.ClassicalCompleteOwnershipHandoverDisabled.selector
        );
        wallet.completeOwnershipHandover(BOB);
    }

    function test_completeOwnershipHandover_revertsWhen_callerNotOwner()
        public
    {
        _requestHandover(BOB);
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_noHandoverRequest()
        public
    {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(SoladyOwnable.NoHandoverRequest.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_handoverExpired()
        public
    {
        _requestHandover(BOB);
        // Solady default handover validity is 48 hours.
        vm.warp(block.timestamp + 48 hours + 1);

        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(SoladyOwnable.NoHandoverRequest.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_newOwnerIsZero()
        public
    {
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            address(0),
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ZeroAddressOwner.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_currentOwnershipKeyMismatch()
        public
    {
        _requestHandover(BOB);
        (
            WOTSPlus.WinternitzAddress memory bogus,
            bytes32 bogusPriv
        ) = _generateKeyPair("bogus-cur-ownership");
        bytes memory payload = _buildPayload(
            bogus,
            bogusPriv,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_newOwnershipKeyEqualsCurrent()
        public
    {
        _requestHandover(BOB);
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            ownershipPubkey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.SameKey.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_newOwnershipKeyIsZero()
        public
    {
        _requestHandover(BOB);
        WOTSPlus.WinternitzAddress memory zero;
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            zero,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownOwnershipKey.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_newDisasterKeyIsZero()
        public
    {
        _requestHandover(BOB);
        WOTSPlus.WinternitzAddress memory zero;
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            zero
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownDisasterRecoveryKey.selector);
        wallet.completeOwnershipHandover(payload);
    }

    function test_completeOwnershipHandover_revertsWhen_invalidSignature()
        public
    {
        _requestHandover(BOB);
        bytes32 keysHash = _keysHash();
        bytes32 msgHash = _buildCompleteOwnershipHandoverMessageHash(
            address(wallet),
            ownershipPubkey,
            newOwnershipKey,
            BOB,
            keysHash
        );
        (, bytes32 wrongPriv) = _generateKeyPair("handover-wrong-signer");
        WOTSPlus.WinternitzElements memory bad = _sign(wrongPriv, msgHash);

        bytes memory payload = Codec.encodeOwnershipTransfer(
            ownershipPubkey,
            newOwnershipKey,
            bad,
            BOB,
            newDisasterKey,
            freshTxnKeys,
            freshRecoveryKeys
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.completeOwnershipHandover(payload);
    }

    /// @dev A signature produced for `completeOwnershipHandover` must not verify when
    ///      replayed through `transferOwnership` (different domain tag).
    function test_completeOwnershipHandover_sigDoesNotReplayToTransfer()
        public
    {
        _requestHandover(BOB);
        bytes memory payload = _buildPayload(
            ownershipPubkey,
            ownershipPrivateKey,
            newOwnershipKey,
            BOB,
            newDisasterKey
        );

        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.transferOwnership(payload);
    }
}
