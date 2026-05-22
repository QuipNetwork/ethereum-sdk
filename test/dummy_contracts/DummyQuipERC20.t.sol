// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipERC20} from "../../contracts/dummy_contracts/DummyQuipERC20.sol";
import {DummyQuipERC20Spender} from "../../contracts/dummy_contracts/DummyQuipERC20Spender.sol";

contract DummyQuipERC20Test is Test {
    DummyQuipERC20 internal token6;
    DummyQuipERC20 internal token18;
    DummyQuipERC20Spender internal spender;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        token6 = new DummyQuipERC20(
            "DummyQuip ERC20 Six Decimals", "tQ6", 6, address(this), true, 10_000 * 10 ** 6
        );
        token18 = new DummyQuipERC20(
            "DummyQuip ERC20 Eighteen Decimals", "tQ18", 18, address(this), true, 10_000 ether
        );
        spender = new DummyQuipERC20Spender();
    }

    function testDecimalsAndPublicFaucet() public {
        token6.faucet(alice, 1_500_000);

        assertEq(token6.decimals(), 6);
        assertEq(token6.balanceOf(alice), 1_500_000);
        assertEq(token6.totalSupply(), 1_500_000);
    }

    function testEighteenDecimalMintAndBurn() public {
        token18.mint(alice, 2 ether);

        assertEq(token18.decimals(), 18);
        assertEq(token18.balanceOf(alice), 2 ether);
        assertEq(token18.totalSupply(), 2 ether);

        vm.prank(alice);
        token18.burn(0.5 ether);

        assertEq(token18.balanceOf(alice), 1.5 ether);
        assertEq(token18.totalSupply(), 1.5 ether);
    }

    function testAnyoneCanMintWithoutCap() public {
        vm.prank(alice);
        token6.mint(bob, 999_999_999_999);

        assertEq(token6.balanceOf(bob), 999_999_999_999);
        assertEq(token6.totalSupply(), 999_999_999_999);
    }

    function testBurnAndBurnFrom() public {
        token6.mint(alice, 1000);
        token6.mint(bob, 500);

        vm.prank(alice);
        token6.burn(300);
        assertEq(token6.balanceOf(alice), 700);
        assertEq(token6.totalSupply(), 1200);

        vm.prank(alice);
        token6.approve(bob, 200);
        vm.prank(bob);
        token6.burnFrom(alice, 200);
        assertEq(token6.balanceOf(alice), 500);
        assertEq(token6.totalSupply(), 1000);
    }

    function testTransferAndMaxAllowanceTransferFrom() public {
        token6.mint(alice, 1000);

        vm.prank(alice);
        token6.transfer(bob, 400);
        assertEq(token6.balanceOf(bob), 400);

        vm.prank(alice);
        token6.approve(address(spender), type(uint256).max);

        spender.pull(address(token6), alice, bob, 100);
        assertEq(token6.balanceOf(alice), 500);
        assertEq(token6.balanceOf(bob), 500);
        assertEq(token6.allowance(alice, address(spender)), type(uint256).max);
    }

    function testFaucetCap() public {
        uint256 amount = 10_001 * 10 ** 6;
        uint256 cap = 10_000 * 10 ** 6;
        vm.expectRevert(abi.encodeWithSelector(DummyQuipERC20.DummyQuipFaucetCapExceeded.selector, amount, cap));
        token6.faucet(alice, amount);
    }

    function testZeroAmountReverts() public {
        vm.expectRevert(DummyQuipERC20.DummyQuipZeroAmount.selector);
        token6.mint(alice, 0);

        token6.mint(alice, 1);
        vm.prank(alice);
        vm.expectRevert(DummyQuipERC20.DummyQuipZeroAmount.selector);
        token6.burn(0);
    }

    function testTransferToZeroAddressReverts() public {
        token6.mint(alice, 1);
        vm.prank(alice);
        vm.expectRevert(DummyQuipERC20.DummyQuipZeroAddress.selector);
        token6.transfer(address(0), 1);
    }

    function testInsufficientBalanceReverts() public {
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(DummyQuipERC20.DummyQuipInsufficientBalance.selector, alice, uint256(0), uint256(1))
        );
        token6.burn(1);
    }

    function testOwnerCanDisableFaucetAndPrivatelyMint() public {
        token6.setFaucetConfig(false, 0);

        vm.expectRevert(DummyQuipERC20.DummyQuipFaucetDisabled.selector);
        token6.faucet(alice, 1);

        token6.ownerMint(alice, 100);
        assertEq(token6.balanceOf(alice), 100);
    }

    function testTransferFromSpenderFlow() public {
        token6.faucet(alice, 1000);

        vm.prank(alice);
        token6.approve(address(spender), 400);

        spender.pull(address(token6), alice, bob, 250);

        assertEq(token6.balanceOf(alice), 750);
        assertEq(token6.balanceOf(bob), 250);
        assertEq(token6.allowance(alice, address(spender)), 150);
    }
}
