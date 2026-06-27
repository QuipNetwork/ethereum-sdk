// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";

contract QuipPaymaster_getDeposit is QuipPaymasterTest {
    function test_getDeposit_returnsEntryPointBalance() public {
        vm.mockCall(
            ENTRY_POINT,
            abi.encodeWithSignature("balanceOf(address)", address(paymaster)),
            abi.encode(uint256(5 ether))
        );
        assertEq(paymaster.getDeposit(), 5 ether);
    }

    function test_getDeposit_returnsZeroWhenNoDeposit() public {
        vm.mockCall(
            ENTRY_POINT,
            abi.encodeWithSignature("balanceOf(address)", address(paymaster)),
            abi.encode(uint256(0))
        );
        assertEq(paymaster.getDeposit(), 0);
    }
}
