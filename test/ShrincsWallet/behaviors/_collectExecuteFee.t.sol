// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_collectExecuteFee(maxFee)` (via
///      `exposed_collectExecuteFee`), which reads the factory's LIVE `executeFee` once, reverts
///      `ExecuteFeeExceedsCap` if it exceeds the signer's `maxFee` ceiling, forwards the live fee
///      to the factory otherwise, and is a no-op when the fee is zero. The suite's setUp installs
///      a standing non-zero live fee and funds the wallet; tests that need a different live fee
///      (zero, or above the cap) move it explicitly as their subject.
contract ShrincsWallet__collectExecuteFee is ShrincsWalletTest {
    // The standing live fee installed by this suite's setUp.
    uint256 internal constant EXECUTE_FEE = 0.1 ether;
    // The wallet's funded balance for fee collection.
    uint256 internal constant WALLET_BALANCE = 1 ether;

    function setUp() public override {
        super.setUp();
        _setExecuteFee(EXECUTE_FEE);
        vm.deal(WALLET, WALLET_BALANCE);
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertEq(wallet.getExecuteFee(), EXECUTE_FEE, "standing live fee installed");
        assertEq(WALLET.balance, WALLET_BALANCE, "wallet funded");
    }

    function test_collectExecuteFee_noopWhenZero() public {
        _setExecuteFee(0);
        uint256 walletBefore = WALLET.balance;
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee(0);

        assertEq(WALLET.balance, walletBefore, "no ETH leaves the wallet");
        assertEq(address(factory).balance, factoryBefore, "factory balance unchanged");
    }

    function test_collectExecuteFee_forwardsFeeToFactory() public {
        uint256 walletBefore = WALLET.balance;
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee(EXECUTE_FEE);

        assertEq(walletBefore - WALLET.balance, EXECUTE_FEE, "wallet debited the fee");
        assertEq(address(factory).balance - factoryBefore, EXECUTE_FEE, "factory credited the fee");
    }

    function test_collectExecuteFee_revertsWhen_insufficientBalance() public {
        vm.deal(WALLET, EXECUTE_FEE - 1); // less than the fee
        vm.expectRevert(); // SafeTransferLib.ETHTransferFailed
        wallet.exposed_collectExecuteFee(EXECUTE_FEE);
    }

    function test_collectExecuteFee_chargesLiveFeeBelowCap() public {
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee(EXECUTE_FEE * 5); // headroom above the live fee

        assertEq(
            address(factory).balance - factoryBefore,
            EXECUTE_FEE,
            "LIVE fee charged, not the ceiling"
        );
    }

    function test_collectExecuteFee_revertsWhen_feeExceedsCap() public {
        _setExecuteFee(EXECUTE_FEE * 2); // live fee moved above the signer's cap

        vm.expectRevert(
            abi.encodeWithSelector(
                IShrincsWallet.ExecuteFeeExceedsCap.selector, EXECUTE_FEE * 2, EXECUTE_FEE
            )
        );
        wallet.exposed_collectExecuteFee(EXECUTE_FEE);
    }

    /// @dev Boundary: live fee exactly equal to the cap passes (`<=`, not `<`).
    function test_collectExecuteFee_liveFeeEqualsCap() public {
        uint256 factoryBefore = address(factory).balance;

        wallet.exposed_collectExecuteFee(EXECUTE_FEE);

        assertEq(address(factory).balance - factoryBefore, EXECUTE_FEE, "boundary fee collected");
    }
}
