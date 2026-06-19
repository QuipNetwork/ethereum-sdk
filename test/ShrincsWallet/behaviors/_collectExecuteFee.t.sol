// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_collectExecuteFee` (via `exposed_collectExecuteFee`),
///      which forwards the factory's per-op `executeFee` from the wallet to the factory and is a
///      no-op when the fee is zero.
contract ShrincsWallet__collectExecuteFee is ShrincsWalletTest {
    function test_collectExecuteFee_noopWhenZero() public {
        assertEq(wallet.getExecuteFee(), 0, "default fee is zero");
        vm.deal(WALLET, 1 ether);
        uint256 walletBefore = WALLET.balance;
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee();

        assertEq(WALLET.balance, walletBefore, "no ETH leaves the wallet");
        assertEq(address(factory).balance, factoryBefore, "factory balance unchanged");
    }

    function test_collectExecuteFee_forwardsFeeToFactory() public {
        uint256 fee = 0.25 ether;
        factory.setExecuteFee(fee);
        vm.deal(WALLET, 1 ether);
        uint256 walletBefore = WALLET.balance;
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee();

        assertEq(walletBefore - WALLET.balance, fee, "wallet debited the fee");
        assertEq(address(factory).balance - factoryBefore, fee, "factory credited the fee");
    }

    function test_collectExecuteFee_revertsWhen_insufficientBalance() public {
        factory.setExecuteFee(1 ether);
        vm.deal(WALLET, 0.5 ether); // less than the fee
        vm.expectRevert(); // SafeTransferLib.ETHTransferFailed
        wallet.exposed_collectExecuteFee();
    }
}
