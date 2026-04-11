// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {IPaymaster} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

contract QuipPaymaster_postOp is QuipPaymasterTest {
    function test_postOp_succeedsFromEntryPoint() public {
        vm.prank(ENTRY_POINT);
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, "", 21_000, 10 gwei);
    }

    function test_postOp_succeedsOnOpReverted() public {
        vm.prank(ENTRY_POINT);
        paymaster.postOp(IPaymaster.PostOpMode.opReverted, "", 21_000, 10 gwei);
    }

    function test_postOp_revertsWhen_notEntryPoint() public {
        vm.prank(ALICE);
        vm.expectRevert(IQuipPaymaster.InvalidEntryPoint.selector);
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, "", 21_000, 10 gwei);
    }
}
