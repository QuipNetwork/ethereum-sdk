// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {QuipFactoryHarness} from "../../harness/QuipFactoryHarness.sol";
import {QuipWallet} from "../../../contracts/QuipWallet.sol";

contract QuipFactory___findLatestActive is Test {
    QuipFactoryHarness public factory;
    address public ADMIN = makeAddr("admin");

    function setUp() public {
        vm.deal(ADMIN, 10 ether);
        factory = new QuipFactoryHarness(payable(ADMIN), 0.1 ether);
    }

    function test_exposed_findLatestActive_returnsZeroWhenEmpty() public view {
        assertEq(factory.exposed_findLatestActive(), address(0));
    }

    function test_exposed_findLatestActive_returnsLatestVetted() public {
        QuipWallet impl1 = new QuipWallet(payable(address(factory)));
        QuipWallet impl2 = new QuipWallet(payable(address(factory)));
        QuipWallet impl3 = new QuipWallet(payable(address(factory)));
        vm.startPrank(ADMIN);
        factory.vetImplementation(address(impl1));
        factory.vetImplementation(address(impl2));
        factory.vetImplementation(address(impl3));
        vm.stopPrank();

        assertEq(factory.exposed_findLatestActive(), address(impl3));
    }

    function test_exposed_findLatestActive_skipsDeprecated() public {
        QuipWallet impl1 = new QuipWallet(payable(address(factory)));
        QuipWallet impl2 = new QuipWallet(payable(address(factory)));
        QuipWallet impl3 = new QuipWallet(payable(address(factory)));
        vm.startPrank(ADMIN);
        factory.vetImplementation(address(impl1));
        factory.vetImplementation(address(impl2));
        factory.vetImplementation(address(impl3));
        factory.deprecateImplementation(address(impl3));
        vm.stopPrank();

        assertEq(factory.exposed_findLatestActive(), address(impl2));
    }

    function test_exposed_findLatestActive_returnsZeroWhenAllDeprecated() public {
        QuipWallet impl1 = new QuipWallet(payable(address(factory)));
        vm.startPrank(ADMIN);
        factory.vetImplementation(address(impl1));
        factory.deprecateImplementation(address(impl1));
        vm.stopPrank();

        assertEq(factory.exposed_findLatestActive(), address(0));
    }

    function test_exposed_findLatestActive_returnsReVettedImpl() public {
        QuipWallet impl1 = new QuipWallet(payable(address(factory)));
        vm.startPrank(ADMIN);
        factory.vetImplementation(address(impl1));
        factory.deprecateImplementation(address(impl1));
        factory.vetImplementation(address(impl1)); // re-vet
        vm.stopPrank();

        assertEq(factory.exposed_findLatestActive(), address(impl1));
    }
}
