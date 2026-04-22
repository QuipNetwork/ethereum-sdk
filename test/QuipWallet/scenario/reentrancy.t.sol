// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @dev Malicious contract that attempts reentrancy via receive().
///      Stashes `msg.sender` at callback time so the test can pin the
///      exact reason the re-entry fails: the wallet is calling back, and
///      only the classical owner is authorised to invoke `execute(bytes)`.
contract ReentrantReceiver {
    QuipWallet public target;
    bool public attacked;
    address public callbackSender;

    constructor(QuipWallet target_) {
        target = target_;
    }

    receive() external payable {
        if (!attacked) {
            attacked = true;
            callbackSender = msg.sender;

            try target.execute(bytes("")) {
                // Should not reach here
            } catch {
                // Expected: Unauthorized (not owner)
            }
        }
    }
}

/// @dev Malicious contract that attempts reentrancy via execute callback.
///      Mirrors `ReentrantReceiver` for the contract-call path and captures
///      `msg.sender` to prove the callback runs as the wallet (the lock-out).
contract ReentrantTarget {
    QuipWallet public wallet;
    bool public attacked;
    address public callbackSender;

    constructor(QuipWallet wallet_) {
        wallet = wallet_;
    }

    fallback() external payable {
        if (!attacked) {
            attacked = true;
            callbackSender = msg.sender;

            try wallet.execute(bytes("")) {
                // Should not reach here
            } catch {
                // Expected: Unauthorized (not owner)
            }
        }
    }
}

/// @title Reentrancy Protection Tests
/// @dev Validates that malicious contracts cannot exploit reentrancy via
///      ETH transfers or arbitrary calls in QuipWallet.
contract QuipWallet_reentrancy is QuipWalletTest {
    /// @dev A malicious execute target cannot re-enter execute
    ///      because the callback's msg.sender is the wallet, not the classical owner.
    function test_reentrancy_executeTargetReenters() public {
        ReentrantTarget attacker = new ReentrantTarget(wallet);

        bytes memory callData = abi.encodeWithSignature("trigger()");
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "reentrant-exec"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(attacker),
            0,
            callData,
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(attacker),
                0,
                callData
            )
        );

        // The reentrancy was attempted but failed (Unauthorized)
        assertTrue(
            attacker.attacked(),
            "Reentrancy callback was not triggered"
        );
        // Prove the "why" — the callback's msg.sender is the wallet itself,
        // not the classical owner, so the re-entered `execute` hits `onlyOwner`.
        assertEq(
            attacker.callbackSender(),
            address(wallet),
            "callback msg.sender was not the wallet"
        );

        // Wallet state is consistent — pqOwner was rotated
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));
    }

    /// @dev A malicious transfer recipient cannot re-enter execute
    ///      because the receive() callback's msg.sender is the wallet, not the classical owner.
    function test_reentrancy_transferRecipientReenters() public {
        ReentrantReceiver attacker = new ReentrantReceiver(wallet);

        uint256 transferAmount = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey, ) = _generateKeyPair(
            "reentrant-transfer"
        );

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet),
            alicePubkey,
            nextPubkey,
            address(attacker),
            transferAmount,
            "",
            0
        );
        WOTSPlus.WinternitzElements memory sig = _sign(
            alicePrivateKey,
            msgHash
        );

        vm.prank(ALICE);
        wallet.execute(
            Codec.encodeExecute(
                alicePubkey,
                nextPubkey,
                sig,
                address(attacker),
                transferAmount,
                ""
            )
        );

        // The reentrancy was attempted but failed
        assertTrue(
            attacker.attacked(),
            "Reentrancy callback was not triggered"
        );
        // Prove the "why" — the callback's msg.sender is the wallet, so the
        // re-entered `execute(bytes)` hits `onlyOwner` and reverts.
        assertEq(
            attacker.callbackSender(),
            address(wallet),
            "callback msg.sender was not the wallet"
        );

        // Wallet pqOwner rotated correctly
        assertTrue(wallet.isKey(Codec.KeyType.Transaction, nextPubkey));

        // Attacker received the transfer amount
        assertEq(address(attacker).balance, transferAmount);
    }
}
