// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/wots/WOTSPlusCodec.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";

/// @title withdrawDepositTo Tests
/// @dev Validates that the classical ERC-4337 `withdrawDepositTo(address,uint256)` is blocked
///      and that every PQ-side revert on the WOTS+-authenticated `withdrawDepositTo(bytes)`
///      path triggers correctly. Happy-path / fund-movement / EntryPoint-behavior coverage
///      lives in the fork-based integration suite — every revert below fires inside
///      `onlyOwner` or `_verifyAndRotate`, well before the trailing `ERC4337.withdrawDepositTo`
///      call, so no EntryPoint code or deposit is required here.
contract WOTSPlusImplementation_withdrawDepositTo is WOTSPlusImplementationTest {
    // ── classical path is blocked ────────────────────────────────────

    function test_withdrawDepositTo_revertsWhen_classicalPathCalled() public {
        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.ClassicalWithdrawDisabled.selector);
        wallet.withdrawDepositTo(BOB, 1 ether);
    }

    function test_withdrawDepositTo_revertsWhen_classicalPathCalledByNonOwner() public {
        vm.prank(BOB);
        vm.expectRevert(IWOTSPlusImplementation.ClassicalWithdrawDisabled.selector);
        wallet.withdrawDepositTo(BOB, 1 ether);
    }

    // ── WOTS path: reverts ───────────────────────────────────────────

    function test_withdrawDepositTo_revertsWhen_callerNotOwner() public {
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("not-owner-next");
        bytes memory payload =
            _signWithdraw(alicePubkey, alicePrivateKey, nextKey, BOB, 0.1 ether, address(wallet), block.chainid);

        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.withdrawDepositTo(payload);
    }

    function test_withdrawDepositTo_revertsWhen_invalidSignature() public {
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("invalid-sig-next");
        (, bytes32 wrongPriv) = _generateKeyPair("wrong-key");
        bytes memory payload =
            _signWithdraw(alicePubkey, wrongPriv, nextKey, BOB, 0.1 ether, address(wallet), block.chainid);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.withdrawDepositTo(payload);
    }

    function test_withdrawDepositTo_revertsWhen_currentKeyNotInTransactionSet() public {
        // Stranger key: not a member of any keyset. Sign with its matching
        // private key so WOTS+ verify is not reached — `_enforceContained`
        // catches the membership failure first.
        (WOTSPlus.WinternitzAddress memory stranger, bytes32 strangerPriv) = _generateKeyPair("stranger");
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("stranger-next");

        bytes memory payload =
            _signWithdraw(stranger, strangerPriv, nextKey, BOB, 0.1 ether, address(wallet), block.chainid);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.UnknownKey.selector);
        wallet.withdrawDepositTo(payload);
    }

    function test_withdrawDepositTo_revertsWhen_nextKeyAlreadyInTransactionKeyset() public {
        // aliceTxnPubkeys[1] is still in the active transaction keyset. Auth
        // rotation removes alicePubkey then tries to add the duplicate; the
        // global uniqueness check inside `_safeAddKey` rejects it.
        WOTSPlus.WinternitzAddress memory dup = aliceTxnPubkeys[1];
        bytes memory payload =
            _signWithdraw(alicePubkey, alicePrivateKey, dup, BOB, 0.1 ether, address(wallet), block.chainid);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.withdrawDepositTo(payload);
    }

    function test_withdrawDepositTo_revertsWhen_nextKeyAlreadyInRecoveryKeyset() public {
        WOTSPlus.WinternitzAddress memory dup = recoveryPubkeys[0];
        bytes memory payload =
            _signWithdraw(alicePubkey, alicePrivateKey, dup, BOB, 0.1 ether, address(wallet), block.chainid);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.withdrawDepositTo(payload);
    }

    function test_withdrawDepositTo_revertsWhen_nextKeyEqualsDisasterRecoveryKey() public {
        (WOTSPlus.WinternitzAddress memory disasterKey,) = _generateDisasterRecoveryKey(VAULT_SEED);
        bytes memory payload =
            _signWithdraw(alicePubkey, alicePrivateKey, disasterKey, BOB, 0.1 ether, address(wallet), block.chainid);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.withdrawDepositTo(payload);
    }

    function test_withdrawDepositTo_revertsWhen_nextKeyEqualsOwnershipKey() public {
        bytes memory payload = _signWithdraw(
            alicePubkey, alicePrivateKey, ownershipPubkey, BOB, 0.1 ether, address(wallet), block.chainid
        );

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.KeyInUse.selector);
        wallet.withdrawDepositTo(payload);
    }

    function test_withdrawDepositTo_revertsWhen_currentEqualsNext() public {
        bytes memory payload =
            _signWithdraw(alicePubkey, alicePrivateKey, alicePubkey, BOB, 0.1 ether, address(wallet), block.chainid);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.SameKey.selector);
        wallet.withdrawDepositTo(payload);
    }

    /// @dev Cross-chain binding: a signature signed for chainId X cannot be
    ///      replayed on the same wallet running on chainId Y. The wallet
    ///      computes its digest with `block.chainid`, so the message hash
    ///      mismatches the signed one and WOTS+ verify fails.
    function test_withdrawDepositTo_revertsWhen_signedForDifferentChain() public {
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("xchain-next");

        bytes memory payload =
            _signWithdraw(alicePubkey, alicePrivateKey, nextKey, BOB, 0.1 ether, address(wallet), block.chainid + 1);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.withdrawDepositTo(payload);
    }

    /// @dev Cross-wallet binding: a signature signed against one wallet
    ///      address cannot be replayed against a different wallet, even
    ///      with otherwise identical parameters.
    function test_withdrawDepositTo_revertsWhen_signedForDifferentWallet() public {
        (WOTSPlus.WinternitzAddress memory nextKey,) = _generateKeyPair("xwallet-next");

        bytes memory payload =
            _signWithdraw(alicePubkey, alicePrivateKey, nextKey, BOB, 0.1 ether, address(0xdead), block.chainid);

        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.InvalidSignature.selector);
        wallet.withdrawDepositTo(payload);
    }

    // ── helpers ──────────────────────────────────────────────────────

    /// @dev Build a WOTS+-signed `withdrawDepositTo(bytes)` payload. The
    ///      `walletForDigest` / `chainIdForDigest` parameters are exposed
    ///      separately so cross-binding tests can sign for a domain that
    ///      differs from the wallet's actual `(address(this), block.chainid)`.
    function _signWithdraw(
        WOTSPlus.WinternitzAddress memory currentKey,
        bytes32 currentPriv,
        WOTSPlus.WinternitzAddress memory nextKey,
        address to,
        uint256 amount,
        address walletForDigest,
        uint256 chainIdForDigest
    ) internal pure returns (bytes memory) {
        bytes32 digest = Codec.withdrawDepositDigest(
            walletForDigest,
            chainIdForDigest,
            currentKey.publicSeed,
            currentKey.publicKeyHash,
            nextKey.publicSeed,
            nextKey.publicKeyHash,
            to,
            amount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(currentPriv, digest);
        return Codec.encodeWithdrawDeposit(currentKey, nextKey, sig, to, amount);
    }
}
