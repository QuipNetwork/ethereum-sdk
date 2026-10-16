// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster_addStake is QuipPaymasterTest {
    function test_addStake_stakesWithEntryPoint() public {
        uint256 amount = 1 ether;

        vm.mockCall(ENTRY_POINT, amount, abi.encodeWithSignature("addStake(uint32)", uint32(86_400)), "");

        vm.prank(ADMIN);
        paymaster.addStake{value: amount}(86_400);
    }

    function test_addStake_revertsWhen_notOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.addStake{value: 1 ether}(86_400);
    }
}
