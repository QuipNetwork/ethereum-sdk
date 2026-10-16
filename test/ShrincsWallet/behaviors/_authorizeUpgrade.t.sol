// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Unit tests for `_authorizeUpgrade` (via `exposed_authorizeUpgrade`), the UUPS
///      authorization hook `super.upgradeToAndCall` runs. In this wallet it is defense in depth:
///      the overridden `upgradeToAndCall` is itself `onlyOwner` (and SHRINCS-gated), so this
///      hook's own `onlyOwner` never decides alone — but it must still hold independently.
contract ShrincsWallet__authorizeUpgrade is ShrincsWalletTest {
    function test_exposed_authorizeUpgrade_passesForOwner() public {
        vm.prank(OWNER);
        wallet.exposed_authorizeUpgrade(address(0xBEEF)); // no revert, no state
    }

    function test_exposed_authorizeUpgrade_revertsWhen_notOwner() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        wallet.exposed_authorizeUpgrade(address(0xBEEF));
    }
}
