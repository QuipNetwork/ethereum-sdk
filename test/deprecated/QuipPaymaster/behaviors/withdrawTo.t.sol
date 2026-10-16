// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster_withdrawTo is QuipPaymasterTest {
    function test_withdrawTo_withdrawsFromEntryPoint() public {
        vm.mockCall(ENTRY_POINT, abi.encodeWithSignature("withdrawTo(address,uint256)", BOB, 1 ether), "");

        vm.prank(ADMIN);
        paymaster.withdrawTo(payable(BOB), 1 ether);
    }

    function test_withdrawTo_revertsWhen_notOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.withdrawTo(payable(ALICE), 1 ether);
    }
}
