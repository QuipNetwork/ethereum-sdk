// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_collectExecuteFee(maxFee)` (via
///      `exposed_collectExecuteFee`), which reads the factory's LIVE `executeFee` once, reverts
///      `ExecuteFeeExceedsCap` if it exceeds the signer's `maxFee` ceiling, forwards the live fee
///      to the factory otherwise, and is a no-op when the fee is zero.
contract ShrincsWallet__collectExecuteFee is ShrincsWalletTest {
    function test_collectExecuteFee_noopWhenZero() public {
        assertEq(wallet.getExecuteFee(), 0, "default fee is zero");
        vm.deal(WALLET, 1 ether);
        uint256 walletBefore = WALLET.balance;
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee(0);

        assertEq(WALLET.balance, walletBefore, "no ETH leaves the wallet");
        assertEq(address(factory).balance, factoryBefore, "factory balance unchanged");
    }

    function test_collectExecuteFee_forwardsFeeToFactory() public {
        uint256 fee = 0.25 ether;
        factory.setExecuteFee(fee);
        vm.deal(WALLET, 1 ether);
        uint256 walletBefore = WALLET.balance;
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee(fee);

        assertEq(walletBefore - WALLET.balance, fee, "wallet debited the fee");
        assertEq(address(factory).balance - factoryBefore, fee, "factory credited the fee");
    }

    function test_collectExecuteFee_revertsWhen_insufficientBalance() public {
        factory.setExecuteFee(1 ether);
        vm.deal(WALLET, 0.5 ether); // less than the fee
        vm.expectRevert(); // SafeTransferLib.ETHTransferFailed
        wallet.exposed_collectExecuteFee(1 ether);
    }

    function test_collectExecuteFee_chargesLiveFeeBelowCap() public {
        factory.setExecuteFee(0.1 ether);
        vm.deal(WALLET, 1 ether);
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee(0.5 ether); // headroom above the live fee

        assertEq(address(factory).balance - factoryBefore, 0.1 ether, "LIVE fee charged, not the ceiling");
    }

    function test_collectExecuteFee_revertsWhen_feeExceedsCap() public {
        factory.setExecuteFee(0.2 ether);
        vm.deal(WALLET, 1 ether);

        vm.expectRevert(
            abi.encodeWithSelector(IShrincsWallet.ExecuteFeeExceedsCap.selector, 0.2 ether, 0.1 ether)
        );
        wallet.exposed_collectExecuteFee(0.1 ether);
    }

    /// @dev Boundary: live fee exactly equal to the cap passes (`<=`, not `<`).
    function test_collectExecuteFee_liveFeeEqualsCap() public {
        factory.setExecuteFee(0.1 ether);
        vm.deal(WALLET, 1 ether);
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee(0.1 ether);

        assertEq(address(factory).balance - factoryBefore, 0.1 ether, "boundary fee collected");
    }
}
