// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the ShrincsWallet constructor — the two explicit revert branches
///      (zero factory, zero verifier) and the happy-path immutable assignments.
contract ShrincsWallet_constructor is ShrincsWalletTest {
    function test_constructor_setsImmutables() public {
        ShrincsWalletHarness fresh =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        assertEq(fresh.FACTORY(), address(factory), "factory immutable");
        assertEq(fresh.SHRINCS_VERIFIER(), address(shrincsVerifier), "verifier immutable");
        assertEq(fresh.getShrincsVerifier(), address(shrincsVerifier), "verifier view getter");
    }

    function test_constructor_revertsWhen_factoryZero() public {
        vm.expectRevert(IShrincsWallet.ZeroAddressFactory.selector);
        new ShrincsWalletHarness(payable(address(0)), address(shrincsVerifier));
    }

    function test_constructor_revertsWhen_verifierZero() public {
        vm.expectRevert(IShrincsWallet.ZeroAddressVerifier.selector);
        new ShrincsWalletHarness(payable(address(factory)), address(0));
    }
}
