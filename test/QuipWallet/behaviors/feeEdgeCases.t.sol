// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @title Fee Edge Case Tests
/// @dev Validates fee-related edge cases: fee changes between sign and execute,
///      zero fees, and fee accounting accuracy.
contract QuipWallet_feeEdgeCases is QuipWalletTest {
    /// @dev Admin raises transfer fee after user signs but before execution.
    ///      The wallet reads the fee live from the factory, so the higher fee applies.
    function test_feeEdgeCases_transferFeeChangedBetweenSignAndExecute() public {
        // Set initial low fee
        vm.prank(ADMIN);
        factory.setTransferFee(0.001 ether);

        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("fee-change-key");

        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        // Admin raises fee before Alice's tx lands
        vm.prank(ADMIN);
        factory.setTransferFee(0.05 ether);

        // Execute — the higher fee applies
        uint256 walletBalBefore = address(wallet).balance;
        uint256 factoryBalBefore = address(factory).balance;

        vm.prank(ALICE);
        wallet.transferWithWinternitz(nextPubkey, sig, payable(BOB), transferAmount);

        // Factory collected the higher fee
        assertEq(address(factory).balance, factoryBalBefore + 0.05 ether);
        assertEq(address(wallet).balance, walletBalBefore - transferAmount - 0.05 ether);
    }

    /// @dev When transfer fee is 0, no ETH should be sent to the factory.
    function test_feeEdgeCases_zeroTransferFee() public {
        // Fee defaults to 0 in setUp
        assertEq(factory.transferFee(), 0);

        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("zero-fee-transfer");

        bytes32 msgHash = _buildTransferMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 factoryBalBefore = address(factory).balance;
        uint256 walletBalBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.transferWithWinternitz(nextPubkey, sig, payable(BOB), transferAmount);

        assertEq(address(factory).balance, factoryBalBefore);
        assertEq(address(wallet).balance, walletBalBefore - transferAmount);
    }

    /// @dev When execute fee is 0, full msg.value should be forwarded to target.
    function test_feeEdgeCases_zeroExecuteFee() public {
        assertEq(factory.executeFee(), 0);

        DummyContract dummy = new DummyContract();
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector, 42
        );
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("zero-fee-execute");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 factoryBalBefore = address(factory).balance;

        vm.prank(ALICE);
        wallet.executeWithWinternitz(nextPubkey, sig, payable(address(dummy)), callData);

        // No fee collected
        assertEq(address(factory).balance, factoryBalBefore);
        assertEq(dummy.value(), 42);
    }
}
