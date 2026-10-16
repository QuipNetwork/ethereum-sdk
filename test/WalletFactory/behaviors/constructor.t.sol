// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactory} from "../../../contracts/WalletFactory.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";

/// @dev Behaviour tests for the WalletFactory constructor (per-implementation
///      immutable `MAX_FEE` + its single revert branch) and `initialize`
///      (proxy-side owner installation).
contract WalletFactory_constructor is WalletFactoryTest {
    function test_constructor_revertsWhen_maxFeeZero() public {
        vm.expectRevert(IWalletFactory.ZeroMaxFee.selector);
        new WalletFactory(0);
    }

    function test_constructor_setsMaxFeeImmutable() public {
        WalletFactory fresh = new WalletFactory(0.5 ether);
        assertEq(fresh.MAX_FEE(), 0.5 ether);
    }

    function test_initialize_setsInitialOwner() public {
        address freshOwner = makeAddr("fresh-owner");
        WalletFactory impl = new WalletFactory(1 ether);
        WalletFactory fresh = WalletFactory(payable(LibClone.deployERC1967(address(impl))));
        fresh.initialize(payable(freshOwner));
        assertEq(fresh.owner(), freshOwner);
        // MAX_FEE reads through the proxy from implementation code.
        assertEq(fresh.MAX_FEE(), 1 ether);
    }

    function test_initialize_revertsWhen_zeroOwner() public {
        WalletFactory impl = new WalletFactory(1 ether);
        WalletFactory fresh = WalletFactory(payable(LibClone.deployERC1967(address(impl))));
        vm.expectRevert(IWalletFactory.ZeroAddressOwner.selector);
        fresh.initialize(payable(address(0)));
    }
}
