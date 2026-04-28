// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @title Signature Replay Protection Tests
/// @dev Validates that WOTS+ signatures cannot be replayed across wallets,
///      chains, operations, or after key rotation.
contract QuipWallet_signatureReplay is QuipWalletTest {
    /// @dev After rotating the key, an old signature for the previous pqOwner
    ///      must not be accepted.
    function test_signatureReplay_oldSignatureFailsAfterKeyRotation() public {
        uint256 transferAmount = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "next-key-1"
        );

        // Build a valid execute (transfer) signature with alicePrivateKey
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            transferAmount,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        // Consume alicePubkey via a benign execute that rotates it out of the
        // transaction set.
        (
            WOTSPlus.WinternitzAddress memory rotatedPubkey,
            bytes32 rotatedPrivKey
        ) = _generateKeyPair("rotated-key");
        uint256 rotateFee = wallet.getExecuteFee();
        bytes32 rotateMsgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            rotatedPubkey,
            BOB,
            0,
            "",
            rotateFee
        );
        WOTSPlus.WinternitzElements memory rotateSig = _sign(
            alicePrivateKey,
            rotateMsgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                rotatedPubkey,
                rotateSig,
                BOB,
                0,
                ""
            )
        );

        // Now try to replay the original signature — alicePubkey was consumed
        // by the rotation above, so it is no longer a member of the set.
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                transferAmount,
                ""
            )
        );
    }

    /// @dev A signature computed for wallet A must not work on wallet B,
    ///      even if both share the same initial pqOwner.
    function test_signatureReplay_crossWalletSignatureFails() public {
        // Deploy a second wallet for BOB using a DIFFERENT seed but same recovery structure
        (
            address bobWalletAddr,
            WOTSPlus.WinternitzAddress memory bobPubkey,
            bytes32 bobPrivateKey,

        ) = _createWallet(BOB, "bob-replay-vault", INITIAL_DEPOSIT);

        // Build a valid execute signature for ALICE's wallet
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "next-key-cross"
        );
        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            0.1 ether,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        // Try to use Alice's signature on Bob's wallet — alicePubkey is not
        // a transaction key in Bob's wallet, so it fails at the key-set check
        // before signature verification.
        QuipWallet bobWallet = QuipWallet(payable(bobWalletAddr));
        vm.prank(BOB);
        vm.expectRevert(IQuipWallet.UnknownKey.selector);
        bobWallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                BOB,
                0.1 ether,
                ""
            )
        );
    }

    /// @dev A signature for a pure transfer (empty data) cannot be used for a
    ///      contract call (non-empty data), because the dataHash differs.
    function test_signatureReplay_dataHashDifferentiatesOperations() public {
        uint256 value = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "next-key-cross-op"
        );

        // Build a signature for a pure transfer (empty data)
        bytes32 transferMsgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            BOB,
            value,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory transferSig = _sign(
            alicePrivateKey,
            transferMsgHash
        );

        // Try using it for a call with non-empty data — different dataHash
        bytes memory callData = abi.encodeWithSignature("nonExistent()");
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                transferSig,
                BOB,
                value,
                callData
            )
        );
    }
}
