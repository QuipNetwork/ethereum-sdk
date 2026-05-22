// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {DummyQuipERC20} from "../../contracts/dummy_contracts/DummyQuipERC20.sol";
import {DummyQuipERC20Spender} from "../../contracts/dummy_contracts/DummyQuipERC20Spender.sol";

contract DummyQuipERC20SpenderTest is Test {
    DummyQuipERC20 internal token;
    DummyQuipERC20Spender internal spender;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        token = new DummyQuipERC20("tQ", "tQ", 6, address(this), true, type(uint256).max);
        spender = new DummyQuipERC20Spender();
        token.mint(alice, 1000);
    }

    function testPullToSelf() public {
        vm.prank(alice);
        token.approve(address(spender), 300);

        spender.pullToSelf(address(token), alice, 300);

        assertEq(token.balanceOf(address(spender)), 300);
        assertEq(token.balanceOf(alice), 700);
        assertEq(spender.allowanceOf(address(token), alice), 0);
    }

    function testTokenBalanceView() public view {
        assertEq(spender.tokenBalance(address(token), alice), 1000);
    }

    function testPullRevertsWithoutAllowance() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                DummyQuipERC20.DummyQuipInsufficientAllowance.selector,
                alice,
                address(spender),
                uint256(0),
                uint256(1)
            )
        );
        spender.pull(address(token), alice, bob, 1);
    }

    function testNativeValueReverts() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(spender).call{value: 1}(
            abi.encodeWithSelector(spender.pull.selector, address(token), alice, bob, uint256(1))
        );
        assertFalse(ok);
    }
}
