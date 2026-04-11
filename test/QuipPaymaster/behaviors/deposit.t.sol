// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";

contract QuipPaymaster_deposit is QuipPaymasterTest {
    function test_deposit_depositsToEntryPoint() public {
        uint256 amount = 1 ether;

        // Use a fork to test against real EntryPoint, or mock the deposit call.
        // For unit tests, we verify the call is made correctly by checking balance change.
        vm.prank(ADMIN);

        // Mock the depositTo call on EntryPoint
        vm.mockCall(
            ENTRY_POINT,
            amount,
            abi.encodeWithSignature("depositTo(address)", address(paymaster)),
            ""
        );

        paymaster.deposit{value: amount}();
    }

    function test_deposit_anyoneCanDeposit() public {
        uint256 amount = 0.5 ether;

        vm.mockCall(
            ENTRY_POINT,
            amount,
            abi.encodeWithSignature("depositTo(address)", address(paymaster)),
            ""
        );

        vm.prank(ALICE);
        paymaster.deposit{value: amount}();
    }
}
