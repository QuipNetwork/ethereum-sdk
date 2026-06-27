// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster_unlockStake is QuipPaymasterTest {
    function test_unlockStake_unlocks() public {
        vm.mockCall(ENTRY_POINT, abi.encodeWithSignature("unlockStake()"), "");

        vm.prank(ADMIN);
        paymaster.unlockStake();
    }

    function test_unlockStake_revertsWhen_notOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.unlockStake();
    }
}
