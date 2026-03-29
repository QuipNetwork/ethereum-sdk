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
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-1");

        // Build a valid transfer signature with alicePrivateKey
        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        // Rotate key via changePqOwner (consumes a different signature)
        (WOTSPlus.WinternitzAddress memory rotatedPubkey, bytes32 rotatedPrivKey) =
            _generateKeyPair("rotated-key");
        bytes32 rotateMsgHash = _buildChangePqOwnerMessageHash(
            address(wallet), alicePubkey, rotatedPubkey
        );
        WOTSPlus.WinternitzElements memory rotateSig = _sign(alicePrivateKey, rotateMsgHash);

        vm.prank(ALICE);
        wallet.changePqOwner(rotatedPubkey, rotateSig);

        // Now try to replay the original transfer signature — pqOwner has changed
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.transferWithWinternitz(nextPubkey, sig, payable(BOB), transferAmount);
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

        // Build a valid transfer signature for ALICE's wallet
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-cross");
        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, 0.1 ether
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        // Try to use Alice's signature on Bob's wallet — digest includes wallet address
        QuipWallet bobWallet = QuipWallet(payable(bobWalletAddr));
        vm.prank(BOB);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        bobWallet.transferWithWinternitz(nextPubkey, sig, payable(BOB), 0.1 ether);
    }

    /// @dev A transfer signature cannot be used for executeWithWinternitz,
    ///      because each operation type uses a different digest tag.
    function test_signatureReplay_crossOperationSignatureFails() public {
        uint256 transferAmount = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("next-key-cross-op");

        // Build a transfer signature
        bytes32 transferMsgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory transferSig = _sign(alicePrivateKey, transferMsgHash);

        // Try using it for an execute call — different digest tag
        bytes memory callData = abi.encodeWithSignature("nonExistent()");
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.InvalidSignature.selector);
        wallet.executeWithWinternitz(
            nextPubkey, transferSig, payable(BOB), callData
        );
    }

    /// @dev Transfer digest must include chainId so signatures are invalid on forks.
    function test_signatureReplay_chainIdInDigest() public {
        bytes32 digest1 = Codec.transferDigest(
            address(wallet), block.chainid,
            alicePubkey.publicSeed, alicePubkey.publicKeyHash,
            bytes32(uint256(1)), bytes32(uint256(2)),
            BOB, 0.1 ether
        );

        bytes32 digest2 = Codec.transferDigest(
            address(wallet), block.chainid + 1,
            alicePubkey.publicSeed, alicePubkey.publicKeyHash,
            bytes32(uint256(1)), bytes32(uint256(2)),
            BOB, 0.1 ether
        );

        assertTrue(digest1 != digest2, "Digests must differ across chain IDs");
    }
}
