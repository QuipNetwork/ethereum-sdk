// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {PreQSalt1Wallets} from "../contracts/PreQSalt1Wallets.sol";
import {IPreQSalt1Wallets} from "../contracts/interfaces/IPreQSalt1Wallets.sol";

/// @title PreQSalt1Wallets Base Test
/// @dev Base contract for testing PreQSalt1Wallets.
contract PreQSalt1WalletsTest is Test {
    PreQSalt1Wallets public registry;

    address public ADMIN = makeAddr("admin");
    address public ALICE = makeAddr("alice");
    address public BOB = makeAddr("bob");

    bytes32 public constant ID = keccak256("legacy-id");
    bytes32 public constant STATEFUL_C = keccak256("stateful");
    bytes32 public constant STATELESS_C = keccak256("stateless");
    bytes32 public constant STATEFUL_C2 = keccak256("stateful-2");
    bytes32 public constant STATELESS_C2 = keccak256("stateless-2");

    function setUp() public virtual {
        registry = new PreQSalt1Wallets(ADMIN);
    }

    function test_setUp() public view virtual {
        assertEq(registry.owner(), ADMIN);
        assertFalse(registry.isWhitelisted(ID));
    }

    function test_add_storesEntry() public {
        vm.expectEmit(true, true, false, true, address(registry));
        emit IPreQSalt1Wallets.Whitelisted(ID, ALICE, STATEFUL_C, STATELESS_C);
        vm.prank(ADMIN);
        registry.add(ID, ALICE, STATEFUL_C, STATELESS_C);

        (address owner, bytes32 statefulC, bytes32 statelessC) = registry.get(
            ID
        );
        assertEq(owner, ALICE);
        assertEq(statefulC, STATEFUL_C);
        assertEq(statelessC, STATELESS_C);
        assertTrue(registry.isWhitelisted(ID));
    }

    function test_add_revertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        registry.add(ID, ALICE, STATEFUL_C, STATELESS_C);
    }

    function test_add_revertsWhen_zeroOwner() public {
        vm.prank(ADMIN);
        vm.expectRevert(IPreQSalt1Wallets.ZeroOwner.selector);
        registry.add(ID, address(0), STATEFUL_C, STATELESS_C);
    }

    function test_remove_clearsEntry() public {
        vm.prank(ADMIN);
        registry.add(ID, ALICE, STATEFUL_C, STATELESS_C);

        vm.expectEmit(true, false, false, false, address(registry));
        emit IPreQSalt1Wallets.Unwhitelisted(ID);
        vm.prank(ADMIN);
        registry.remove(ID);

        (address owner, bytes32 statefulC, bytes32 statelessC) = registry.get(
            ID
        );
        assertEq(owner, address(0));
        assertEq(statefulC, bytes32(0));
        assertEq(statelessC, bytes32(0));
        assertFalse(registry.isWhitelisted(ID));
    }

    function test_remove_revertsWhen_notWhitelisted() public {
        vm.prank(ADMIN);
        vm.expectRevert(IPreQSalt1Wallets.NotWhitelisted.selector);
        registry.remove(ID);
    }

    function test_get_returnsZerosWhen_absent() public view {
        (address owner, bytes32 statefulC, bytes32 statelessC) = registry.get(
            ID
        );
        assertEq(owner, address(0));
        assertEq(statefulC, bytes32(0));
        assertEq(statelessC, bytes32(0));
        assertFalse(registry.isWhitelisted(ID));
    }

    function test_add_overwritesExisting() public {
        vm.prank(ADMIN);
        registry.add(ID, ALICE, STATEFUL_C, STATELESS_C);

        vm.expectEmit(true, true, false, true, address(registry));
        emit IPreQSalt1Wallets.Whitelisted(ID, BOB, STATEFUL_C2, STATELESS_C2);
        vm.prank(ADMIN);
        registry.add(ID, BOB, STATEFUL_C2, STATELESS_C2);

        (address owner, bytes32 statefulC, bytes32 statelessC) = registry.get(
            ID
        );
        assertEq(owner, BOB);
        assertEq(statefulC, STATEFUL_C2);
        assertEq(statelessC, STATELESS_C2);
        assertTrue(registry.isWhitelisted(ID));
    }
}
