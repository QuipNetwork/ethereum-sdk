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

    function test_exposed_findLatestActive_returnsZeroWhenAllDeprecated() public {
        QuipWallet impl1 = new QuipWallet(payable(address(harness)));
        vm.startPrank(ADMIN);
        harness.vetImplementation(address(impl1));
        harness.deprecateImplementation(address(impl1));
        vm.stopPrank();

        assertEq(harness.exposed_findLatestActive(), address(0));
    }

    function test_exposed_findLatestActive_returnsReVettedImpl() public {
        QuipWallet impl1 = new QuipWallet(payable(address(harness)));
        vm.startPrank(ADMIN);
        harness.vetImplementation(address(impl1));
        harness.deprecateImplementation(address(impl1));
        harness.vetImplementation(address(impl1)); // re-vet
        vm.stopPrank();

        assertEq(harness.exposed_findLatestActive(), address(impl1));
    }
}
