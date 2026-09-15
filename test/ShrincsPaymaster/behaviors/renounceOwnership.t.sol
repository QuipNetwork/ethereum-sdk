// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the disabled `renounceOwnership` (INVARIANTS §12). Every admin path on
///      the paymaster is owner-gated with no alternate access, so the override must make the
///      inherited renounce unreachable for the owner while keeping Solady's `onlyOwner` gate for
///      everyone else — the same shape as `WalletFactory` and `ShrincsWallet`.
contract ShrincsPaymaster_renounceOwnership is ShrincsPaymasterTest {
    function test_renounceOwnership_revertsWhen_calledByOwner() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsPaymaster.RenounceDisabled.selector);
        paymaster.renounceOwnership();
        assertEq(paymaster.owner(), OWNER, "owner unchanged");
    }

    function test_renounceOwnership_revertsWhen_calledByNonOwner() public {
        vm.prank(makeAddr("nonOwner"));
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.renounceOwnership();
        assertEq(paymaster.owner(), OWNER, "owner unchanged");
    }
}
