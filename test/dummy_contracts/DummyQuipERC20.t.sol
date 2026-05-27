// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipERC20} from "../../contracts/dummy_contracts/DummyQuipERC20.sol";
import {IERC20Errors} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC6093.sol";

contract DummyQuipERC20Test is Test {
    DummyQuipERC20 internal token;
    address internal alice = address(0xBEEF);
    address internal bob = address(0xCAFE);

    uint8 internal constant DECIMALS = 6;

    function setUp() public {
        token = new DummyQuipERC20("DummyQuip", "tQ", DECIMALS);
    }

    function testMetadata() public view {
        assertEq(token.name(), "DummyQuip");
        assertEq(token.symbol(), "tQ");
        assertEq(token.decimals(), DECIMALS);
        assertEq(token.totalSupply(), 0);
    }

    function testMintAcceptsArbitraryAmounts() public {
        vm.prank(alice);
        token.mint(bob, 1_000_000);
        assertEq(token.balanceOf(bob), 1_000_000);
        assertEq(token.totalSupply(), 1_000_000);
    }

    function testMintIsUngated() public {
        vm.prank(alice);
        token.mint(alice, 1);
        vm.prank(bob);
        token.mint(bob, 1);
        assertEq(token.balanceOf(alice), 1);
        assertEq(token.balanceOf(bob), 1);
    }

    function testTransfer() public {
        vm.prank(alice);
        token.mint(alice, 1_000);

        vm.prank(alice);
        token.transfer(bob, 400);

        assertEq(token.balanceOf(alice), 600);
        assertEq(token.balanceOf(bob), 400);
    }

    function testTransferInsufficientBalanceUsesOZError() public {
        vm.prank(alice);
        token.mint(alice, 100);

        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientBalance.selector, alice, 100, 101
            )
        );
        token.transfer(bob, 101);
    }

    function testTransferFromRequiresAllowance() public {
        vm.prank(alice);
        token.mint(alice, 1_000);

        vm.prank(bob);
        vm.expectRevert(
            abi.encodeWithSelector(
                IERC20Errors.ERC20InsufficientAllowance.selector, bob, 0, 100
            )
        );
        token.transferFrom(alice, bob, 100);
    }

    function testTransferFromWithAllowance() public {
        vm.prank(alice);
        token.mint(alice, 1_000);

        vm.prank(alice);
        token.approve(bob, 250);

        vm.prank(bob);
        token.transferFrom(alice, bob, 250);

        assertEq(token.balanceOf(alice), 750);
        assertEq(token.balanceOf(bob), 250);
        assertEq(token.allowance(alice, bob), 0);
    }

    function testBurn() public {
        vm.prank(alice);
        token.mint(alice, 500);

        vm.prank(alice);
        token.burn(200);

        assertEq(token.balanceOf(alice), 300);
        assertEq(token.totalSupply(), 300);
    }

    function testBurnFromRequiresAllowance() public {
        vm.prank(alice);
        token.mint(alice, 500);

        vm.prank(alice);
        token.approve(bob, 100);

        vm.prank(bob);
        token.burnFrom(alice, 100);

        assertEq(token.balanceOf(alice), 400);
        assertEq(token.allowance(alice, bob), 0);
    }
}
