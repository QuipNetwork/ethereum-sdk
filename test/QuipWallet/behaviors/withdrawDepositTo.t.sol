// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

/// @title withdrawDepositTo Tests
/// @dev Validates that the classical ERC-4337 `withdrawDepositTo(address,uint256)` is blocked
///      and only the WOTS+-authenticated `withdrawDepositTo(bytes)` path is permitted.
contract QuipWallet_withdrawDepositTo is QuipWalletTest {
    function test_withdrawDepositTo_revertsWhen_classicalPathCalled() public {
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.ClassicalWithdrawDisabled.selector);
        wallet.withdrawDepositTo(BOB, 1 ether);
    }

    function test_withdrawDepositTo_revertsWhen_classicalPathCalledByNonOwner() public {
        vm.prank(BOB);
        vm.expectRevert(IQuipWallet.ClassicalWithdrawDisabled.selector);
        wallet.withdrawDepositTo(BOB, 1 ether);
    }
}
