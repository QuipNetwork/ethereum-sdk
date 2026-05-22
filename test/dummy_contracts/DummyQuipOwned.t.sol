// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipOwned} from "../../contracts/dummy_contracts/DummyQuipOwned.sol";
import {DummyQuipOwnedHarness} from "./harness/DummyQuipOwnedHarness.sol";

contract DummyQuipOwnedTest is Test {
    DummyQuipOwnedHarness internal owned;
    address internal alice = address(0xA11CE);

    function setUp() public {
        owned = new DummyQuipOwnedHarness(address(this));
    }

    function testConstructorSetsOwner() public view {
        assertEq(owned.owner(), address(this));
    }

    function testConstructorRejectsZeroOwner() public {
        vm.expectRevert(DummyQuipOwned.DummyQuipZeroOwner.selector);
        new DummyQuipOwnedHarness(address(0));
    }

    function testTransferOwnership() public {
        owned.transferOwnership(alice);
        assertEq(owned.owner(), alice);
    }

    function testOnlyOwnerRevertsForNonOwner() public {
        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(DummyQuipOwned.DummyQuipNotOwner.selector, alice));
        owned.transferOwnership(alice);
    }

    function testTransferOwnershipRejectsZeroAddress() public {
        vm.expectRevert(DummyQuipOwned.DummyQuipZeroOwner.selector);
        owned.transferOwnership(address(0));
    }
}
