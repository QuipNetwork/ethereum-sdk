// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

/// @dev Distinct codehash from WOTSPlusImplementation. `vetImplementationWithPolicy`
///      only needs deployed code.
contract DummyImpl {}

contract WalletFactory_vetImplementationWithPolicy is WalletFactoryTest {
    function test_vetImplementationWithPolicy_setsFlagAndEmits() public {
        DummyImpl d = new DummyImpl();
        bytes32 ch = address(d).codehash;

        vm.expectEmit(true, false, false, true, address(factory));
        emit IWalletFactory.ImplementationPolicySet(ch, true);
        vm.prank(ADMIN);
        factory.vetImplementationWithPolicy(address(d), true);

        assertEq(factory.vettedWalletImpls(ch), address(d));
        assertTrue(factory.getVettedCodeIndex(ch) != type(uint256).max);
    }

    function test_vetImplementationWithPolicy_revertsWhen_callerNotOwner() public {
        DummyImpl d = new DummyImpl();
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.vetImplementationWithPolicy(address(d), true);
    }

    function test_vetImplementationWithPolicy_revertsWhen_emptyCode() public {
        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.EmptyCode.selector);
        factory.vetImplementationWithPolicy(makeAddr("noCode"), true);
    }

    function test_vetImplementationWithPolicy_revertsWhen_alreadyVetted() public {
        DummyImpl d = new DummyImpl();
        vm.prank(ADMIN);
        factory.vetImplementationWithPolicy(address(d), true);

        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.AlreadyVetted.selector);
        factory.vetImplementationWithPolicy(address(d), true);
    }
}
