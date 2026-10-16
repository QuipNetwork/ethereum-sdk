// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {QuipPaymasterHarness} from "../../harness/QuipPaymasterHarness.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster__authorizeUpgrade is QuipPaymasterTest {
    function test_exposed_authorizeUpgrade_succeedsForOwner() public {
        address newImpl = makeAddr("newImpl");
        vm.prank(ADMIN);
        harness.exposed_authorizeUpgrade(newImpl);
    }

    function test_exposed_authorizeUpgrade_revertsWhen_notOwner() public {
        address newImpl = makeAddr("newImpl");
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        harness.exposed_authorizeUpgrade(newImpl);
    }
}
