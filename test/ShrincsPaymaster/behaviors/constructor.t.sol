// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterHarness} from "../../harness/ShrincsPaymasterHarness.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the ShrincsPaymaster constructor — the single explicit revert
///      branch (zero verifier) and the happy-path immutable assignment.
contract ShrincsPaymaster_constructor is ShrincsPaymasterTest {
    function test_constructor_setsVerifierImmutable() public {
        ShrincsPaymasterHarness fresh =
            new ShrincsPaymasterHarness(address(shrincsVerifier));
        assertEq(fresh.SHRINCS_VERIFIER(), address(shrincsVerifier), "verifier immutable");
    }

    function test_constructor_revertsWhen_verifierZero() public {
        vm.expectRevert(IShrincsPaymaster.ZeroAddressVerifier.selector);
        new ShrincsPaymasterHarness(address(0));
    }
}
