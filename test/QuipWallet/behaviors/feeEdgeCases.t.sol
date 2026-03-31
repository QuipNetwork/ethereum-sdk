// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {DummyContract} from "../../../contracts/test/DummyContract.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusCodec as Codec} from "../../../contracts/WOTSPlusCodec.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @title Fee Edge Case Tests
/// @dev Validates fee-related edge cases: fee changes between sign and execute,
///      zero fees, and fee accounting accuracy.
contract QuipWallet_feeEdgeCases is QuipWalletTest {
    /// @dev Admin raises execute fee after user signs but before execution.
    ///      The wallet reads the fee live from the factory, so the higher fee applies.
    function test_feeEdgeCases_executeFeeChangedBetweenSignAndExecute() public {
        // Set initial low fee
        vm.prank(ADMIN);
        factory.setExecuteFee(0.001 ether);

        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("fee-change-key");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount, ""
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        // Admin raises fee before Alice's tx lands
        vm.prank(ADMIN);
        factory.setExecuteFee(0.05 ether);

        // Execute — the higher fee applies
        uint256 walletBalBefore = address(wallet).balance;
        uint256 factoryBalBefore = address(factory).balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(nextPubkey, sig, BOB, transferAmount, ""));

        // Factory collected the higher fee
        assertEq(address(factory).balance, factoryBalBefore + 0.05 ether);
        assertEq(address(wallet).balance, walletBalBefore - transferAmount - 0.05 ether);
    }

    /// @dev When execute fee is 0, no ETH should be sent to the factory for pure transfers.
    function test_feeEdgeCases_zeroFeeTransfer() public {
        assertEq(factory.executeFee(), 0);

        uint256 transferAmount = 0.5 ether;
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("zero-fee-transfer");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, BOB, transferAmount, ""
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 factoryBalBefore = address(factory).balance;
        uint256 walletBalBefore = address(wallet).balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(nextPubkey, sig, BOB, transferAmount, ""));

        assertEq(address(factory).balance, factoryBalBefore);
        assertEq(address(wallet).balance, walletBalBefore - transferAmount);
    }

    /// @dev When execute fee is 0, no ETH should be sent to the factory for calls.
    function test_feeEdgeCases_zeroExecuteFee() public {
        assertEq(factory.executeFee(), 0);

        DummyContract dummy = new DummyContract();
        bytes memory callData = abi.encodeWithSelector(
            DummyContract.setValueNoFee.selector, 42
        );
        (WOTSPlus.WinternitzAddress memory nextPubkey,) = _generateKeyPair("zero-fee-execute");

        bytes32 msgHash = _buildExecuteMessageHash(
            address(wallet), alicePubkey, nextPubkey, address(dummy), 0, callData
        );
        WOTSPlus.WinternitzElements memory sig = _sign(alicePrivateKey, msgHash);

        uint256 factoryBalBefore = address(factory).balance;

        vm.prank(ALICE);
        wallet.execute(Codec.encodeExecute(nextPubkey, sig, address(dummy), 0, callData));

        // No fee collected
        assertEq(address(factory).balance, factoryBalBefore);
        assertEq(dummy.value(), 42);
    }
}
