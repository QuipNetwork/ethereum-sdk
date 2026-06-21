// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the UUPS upgrade authorization gate (`_authorizeUpgrade` is `onlyOwner`).
///      Exercised via the harness because `upgradeToAndCall` itself additionally requires a real
///      proxy (delegatecall) context.
contract ShrincsPaymaster__authorizeUpgrade is ShrincsPaymasterTest {
    function test_authorizeUpgrade_allowsOwner() public {
        vm.prank(OWNER);
        paymaster.exposed_authorizeUpgrade(makeAddr("newImpl")); // must not revert
    }

    function test_authorizeUpgrade_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.exposed_authorizeUpgrade(makeAddr("newImpl"));
    }
}
