// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.28;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity/contracts/WOTSPlus.sol";

contract QuipFactory_withdraw is QuipFactoryTest {
    function setUp() public override {
        super.setUp();

        // Set creation fee and create a wallet to accumulate fees
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Fee Vault");
        (WOTSPlus.WinternitzAddress memory pubkey,) = _generateKeyPair("seed1");

        vm.prank(ALICE);
        factory.depositToWinternitz{value: INITIAL_DEPOSIT + CREATION_FEE}(
            vaultId,
            payable(ALICE),
            pubkey
        );
    }

    function test_setUp() public view override {
        assertEq(factory.admin(), ADMIN);
        assertEq(factory.creationFee(), CREATION_FEE);
        assertTrue(address(factory).balance > 0);
    }

    function test_withdraw_sendsFeesToAdmin() public {
        uint256 adminBalBefore = ADMIN.balance;
        uint256 factoryBal = address(factory).balance;

        vm.prank(ADMIN);
        factory.withdraw(factoryBal);

        assertEq(address(factory).balance, 0);
        assertEq(ADMIN.balance, adminBalBefore + factoryBal);
    }

    function test_withdraw_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert("You aren't the admin");
        factory.withdraw(CREATION_FEE);
    }

    function test_withdraw_revertsWhen_insufficientBalance() public {
        vm.prank(ADMIN);
        vm.expectRevert("Insufficient balance");
        factory.withdraw(1000 ether);
    }
}
