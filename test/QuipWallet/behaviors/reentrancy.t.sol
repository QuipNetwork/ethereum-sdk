// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @dev Malicious contract that attempts reentrancy via receive()
contract ReentrantReceiver {
    QuipWallet public target;
    bool public attacked;

    constructor(QuipWallet target_) {
        target = target_;
    }

    receive() external payable {
        if (!attacked) {
            attacked = true;
            WOTSPlus.WinternitzAddress memory fakePq = WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(uint256(99)),
                publicKeyHash: bytes32(uint256(100))
            });
            WOTSPlus.WinternitzElements memory fakeSig;

            try target.execute(fakePq, fakeSig, payable(address(this)), 0, "") {
                // Should not reach here
            } catch {
                // Expected: Unauthorized (not owner)
            }
        }
    }
}

/// @dev Malicious contract that attempts reentrancy via execute callback
contract ReentrantTarget {
    QuipWallet public wallet;
    bool public attacked;

    constructor(QuipWallet wallet_) {
        wallet = wallet_;
    }

    fallback() external payable {
        if (!attacked) {
            attacked = true;
            WOTSPlus.WinternitzAddress memory fakePq = WOTSPlus.WinternitzAddress({
                publicSeed: bytes32(uint256(99)),
                publicKeyHash: bytes32(uint256(100))
            });
            WOTSPlus.WinternitzElements memory fakeSig;

            try wallet.execute(fakePq, fakeSig, payable(address(this)), 0, "") {
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
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("reentrant-exec");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(attacker), 0, callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.execute(nextPubkey, sig, payable(address(attacker)), 0, callData);

        // The reentrancy was attempted but failed (Unauthorized)
        assertTrue(attacker.attacked(), "Reentrancy callback was triggered");

        // Wallet state is consistent — pqOwner was rotated
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, nextPubkey.publicSeed);
        assertEq(publicKeyHash, nextPubkey.publicKeyHash);
    }

    /// @dev A malicious transfer recipient cannot re-enter execute
    ///      because the receive() callback's msg.sender is the wallet, not the classical owner.
    function test_reentrancy_transferRecipientReenters() public {
        ReentrantReceiver attacker = new ReentrantReceiver(wallet);

        uint256 transferAmount = 0.1 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("reentrant-transfer");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(attacker), transferAmount, ""
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        vm.prank(ALICE);
        wallet.execute(nextPubkey, sig, payable(address(attacker)), transferAmount, "");

        // The reentrancy was attempted but failed
        assertTrue(attacker.attacked(), "Reentrancy callback was triggered");

        // Wallet pqOwner rotated correctly
        (bytes32 publicSeed, bytes32 publicKeyHash) = wallet.pqOwner();
        assertEq(publicSeed, nextPubkey.publicSeed);
        assertEq(publicKeyHash, nextPubkey.publicKeyHash);

        // Attacker received the transfer amount
        assertEq(address(attacker).balance, transferAmount);
    }
}
