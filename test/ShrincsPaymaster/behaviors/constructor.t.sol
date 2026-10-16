// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterHarness} from "../../harness/ShrincsPaymasterHarness.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the ShrincsPaymaster constructor — the two explicit revert
///      branches (zero verifier, codeless verifier) and the happy-path immutable assignment.
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

    /// @dev A non-zero address with no deployed code is rejected. Both EIP-1052 flavours are
    ///      covered: a never-touched address (codehash 0) and a touched EOA (codehash
    ///      keccak256("")) — `code.length` is 0 for both, unlike a `codehash != 0` guard.
    function test_constructor_revertsWhen_verifierCodeless() public {
        address untouched = makeAddr("untouchedVerifier");
        assertEq(untouched.code.length, 0, "precondition: no code");
        vm.expectRevert(IShrincsPaymaster.VerifierHasNoCode.selector);
        new ShrincsPaymasterHarness(untouched);

        address touched = makeAddr("touchedVerifier");
        vm.deal(touched, 1 wei);
        assertEq(touched.code.length, 0, "precondition: touched but no code");
        vm.expectRevert(IShrincsPaymaster.VerifierHasNoCode.selector);
        new ShrincsPaymasterHarness(touched);
    }
}
