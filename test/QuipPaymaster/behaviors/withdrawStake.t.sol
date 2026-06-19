// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster_withdrawStake is QuipPaymasterTest {
    function test_withdrawStake_withdraws() public {
        vm.mockCall(ENTRY_POINT, abi.encodeWithSignature("withdrawStake(address)", BOB), "");

        vm.prank(ADMIN);
        paymaster.withdrawStake(payable(BOB));
    }

    function test_withdrawStake_revertsWhen_notOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.withdrawStake(payable(ALICE));
    }
}
