// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";

contract QuipFactory_withdraw is QuipFactoryTest {
    function setUp() public override {
        super.setUp();

        // Set creation fee and create a wallet to accumulate fees
        vm.prank(ADMIN);
        factory.setCreationFee(CREATION_FEE);

        bytes32 vaultId = keccak256("Fee Vault");
        (WOTSPlus.WinternitzAddress memory pubkey, bytes32 privateKey) = _generateKeyPair("seed1");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(privateKey, 10);

        vm.prank(ALICE);
        factory.depositToWinternitz{value: INITIAL_DEPOSIT + CREATION_FEE}(
            vaultId,
            payable(ALICE),
            pubkey,
            rKeys
        );
    }

    function test_setUp() public view override {
        assertEq(factory.owner(), ADMIN);
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
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ALICE));
        factory.withdraw(CREATION_FEE);
    }

    function test_withdraw_revertsWhen_insufficientBalance() public {
        uint256 bal = address(factory).balance;
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(IQuipFactory.InsufficientBalance.selector, 1000 ether, bal));
        factory.withdraw(1000 ether);
    }
}
