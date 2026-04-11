// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {QuipPaymaster} from "../../../contracts/QuipPaymaster.sol";
import {IQuipPaymaster} from "../../../contracts/interfaces/IQuipPaymaster.sol";
import {Initializable} from "solady-0.1.26/src/utils/Initializable.sol";

contract QuipPaymaster_initialize is QuipPaymasterTest {
    function test_initialize_setsOwner() public view {
        assertEq(paymaster.owner(), ADMIN);
    }

    function test_initialize_emitsPaymasterInitialized() public {
        QuipPaymaster freshImpl = new QuipPaymaster();
        address proxy = _deployProxy(address(freshImpl), keccak256("init-test"));

        vm.expectEmit(true, false, false, false);
        emit IQuipPaymaster.PaymasterInitialized(ADMIN);
        QuipPaymaster(payable(proxy)).initialize(ADMIN);
    }

    function test_initialize_revertsWhen_zeroOwner() public {
        QuipPaymaster freshImpl = new QuipPaymaster();
        address proxy = _deployProxy(address(freshImpl), keccak256("zero-owner"));

        vm.expectRevert(IQuipPaymaster.ZeroAddressOwner.selector);
        QuipPaymaster(payable(proxy)).initialize(address(0));
    }

    function test_initialize_revertsWhen_calledTwice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        paymaster.initialize(ADMIN);
    }

    function test_initialize_revertsWhen_calledOnImplementation() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        implementation.initialize(ADMIN);
    }
}
