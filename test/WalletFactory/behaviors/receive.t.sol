// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";

contract WalletFactory_receive is WalletFactoryTest {
    function test_receive_acceptsEth() public {
        uint256 balanceBefore = address(factory).balance;
        uint256 sendAmount = 1 ether;

        vm.prank(ALICE);
        (bool success,) = address(factory).call{value: sendAmount}("");
        assertTrue(success);

        assertEq(address(factory).balance, balanceBefore + sendAmount);
    }

    function test_receive_acceptsZeroValue() public {
        uint256 balanceBefore = address(factory).balance;

        vm.prank(ALICE);
        (bool success,) = address(factory).call{value: 0}("");
        assertTrue(success);

        assertEq(address(factory).balance, balanceBefore);
    }
}
