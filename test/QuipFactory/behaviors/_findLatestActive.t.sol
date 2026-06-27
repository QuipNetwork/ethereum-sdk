// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {QuipFactoryHarness} from "../../harness/QuipFactoryHarness.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";

contract QuipFactory__findLatestActive is QuipFactoryTest {
    QuipFactoryHarness public harness;

    function setUp() public override {
        super.setUp();
        harness = new QuipFactoryHarness(payable(ADMIN), 0.1 ether);
    }

    function test_exposed_findLatestActive_returnsZeroWhenEmpty() public view {
        assertEq(harness.exposed_findLatestActive(), address(0));
    }

    function test_exposed_findLatestActive_returnsLatestVetted() public {
        QuipWallet impl1 = new QuipWallet(payable(address(harness)));
        QuipWallet impl2 = new QuipWallet(payable(address(harness)));
        QuipWallet impl3 = new QuipWallet(payable(address(harness)));
        vm.startPrank(ADMIN);
        harness.vetImplementation(address(impl1));
        harness.vetImplementation(address(impl2));
        harness.vetImplementation(address(impl3));
        vm.stopPrank();

        assertEq(harness.exposed_findLatestActive(), address(impl3));
    }

    function test_exposed_findLatestActive_skipsDeprecated() public {
        QuipWallet impl1 = new QuipWallet(payable(address(harness)));
        QuipWallet impl2 = new QuipWallet(payable(address(harness)));
        QuipWallet impl3 = new QuipWallet(payable(address(harness)));
        vm.startPrank(ADMIN);
        harness.vetImplementation(address(impl1));
        harness.vetImplementation(address(impl2));
        harness.vetImplementation(address(impl3));
        harness.deprecateImplementation(address(impl3));
        vm.stopPrank();

        assertEq(harness.exposed_findLatestActive(), address(impl2));
    }

    function test_exposed_findLatestActive_returnsZeroWhenAllDeprecated()
        public
    {
        QuipWallet impl1 = new QuipWallet(payable(address(harness)));
        vm.startPrank(ADMIN);
        harness.vetImplementation(address(impl1));
        harness.deprecateImplementation(address(impl1));
        vm.stopPrank();

        assertEq(harness.exposed_findLatestActive(), address(0));
    }

    function test_exposed_findLatestActive_returnsUndeprecatedImpl() public {
        QuipWallet impl1 = new QuipWallet(payable(address(harness)));
        vm.startPrank(ADMIN);
        harness.vetImplementation(address(impl1));
        harness.deprecateImplementation(address(impl1));
        harness.undeprecateImplementation(address(impl1));
        vm.stopPrank();

        assertEq(harness.exposed_findLatestActive(), address(impl1));
    }

    // Pattern: [active, deprecated, deprecated]. The backward scan must walk
    // past *two* consecutive deprecated entries before returning the active
    // one at index 0. `skipsDeprecated` only exercises a single deprecated
    // skip — this case pins the loop-continues invariant when the latest N
    // entries are all deprecated.
    function test_exposed_findLatestActive_skipsMultipleDeprecated() public {
        QuipWallet impl1 = new QuipWallet(payable(address(harness)));
        QuipWallet impl2 = new QuipWallet(payable(address(harness)));
        QuipWallet impl3 = new QuipWallet(payable(address(harness)));
        vm.startPrank(ADMIN);
        harness.vetImplementation(address(impl1));
        harness.vetImplementation(address(impl2));
        harness.vetImplementation(address(impl3));
        harness.deprecateImplementation(address(impl3));
        harness.deprecateImplementation(address(impl2));
        vm.stopPrank();

        assertEq(harness.exposed_findLatestActive(), address(impl1));
    }

    // Pattern: [active, deprecated, active]. Backward scan returns the rightmost
    // active entry without examining earlier entries — guards against a bug
    // where the loop over-shoots the first active hit.
    function test_exposed_findLatestActive_returnsFirstActiveFromRight()
        public
    {
        QuipWallet impl1 = new QuipWallet(payable(address(harness)));
        QuipWallet impl2 = new QuipWallet(payable(address(harness)));
        QuipWallet impl3 = new QuipWallet(payable(address(harness)));
        vm.startPrank(ADMIN);
        harness.vetImplementation(address(impl1));
        harness.vetImplementation(address(impl2));
        harness.vetImplementation(address(impl3));
        harness.deprecateImplementation(address(impl2));
        vm.stopPrank();

        assertEq(harness.exposed_findLatestActive(), address(impl3));
    }
}
