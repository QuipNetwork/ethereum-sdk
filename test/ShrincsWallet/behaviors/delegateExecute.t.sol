// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev `delegateExecute` is permanently disabled (it is the only path that would run un-vetted
///      bytecode in wallet storage and could clear consumed-leaf bits). It reverts for ALL callers.
contract ShrincsWallet_delegateExecute is ShrincsWalletTest {
    function test_delegateExecute_revertsForStranger() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(IShrincsWallet.DelegateExecuteDisabled.selector);
        wallet.delegateExecute(address(0xBEEF), hex"1234");
    }

    function test_delegateExecute_revertsForOwner() public {
        vm.prank(OWNER);
        vm.expectRevert(IShrincsWallet.DelegateExecuteDisabled.selector);
        wallet.delegateExecute(address(0xBEEF), hex"1234");
    }

    function test_delegateExecute_revertsForEntryPoint() public {
        vm.prank(ENTRY_POINT);
        vm.expectRevert(IShrincsWallet.DelegateExecuteDisabled.selector);
        wallet.delegateExecute(address(0xBEEF), "");
    }
}
