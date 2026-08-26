// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract WalletFactory_setPreQSalt1Wallets is WalletFactoryTest {
    function test_setPreQSalt1Wallets_setsAndEmits() public {
        address reg = makeAddr("registry");
        vm.expectEmit(true, false, false, false, address(factory));
        emit IWalletFactory.PreQSalt1WalletsUpdated(reg);
        vm.prank(ADMIN);
        factory.setPreQSalt1Wallets(reg);
        assertEq(factory.preQSalt1Wallets(), reg);
    }

    function test_setPreQSalt1Wallets_revertsWhen_callerNotOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.setPreQSalt1Wallets(makeAddr("registry"));
    }

    function test_setPreQSalt1Wallets_allowsZero() public {
        vm.prank(ADMIN);
        factory.setPreQSalt1Wallets(address(0));
        assertEq(factory.preQSalt1Wallets(), address(0));
    }
}
