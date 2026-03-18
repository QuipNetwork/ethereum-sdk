// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_transferOwnership is QuipWalletTest {
    function test_transferOwnership_setsPendingOwner() public {
        vm.prank(ALICE);
        wallet.transferOwnership(BOB);

        assertEq(wallet.pendingOwner(), BOB);
        assertEq(wallet.owner(), ALICE);
    }

    function test_transferOwnership_acceptOwnership_completesTransfer() public {
        vm.prank(ALICE);
        wallet.transferOwnership(BOB);

        vm.prank(BOB);
        wallet.acceptOwnership();

        assertEq(wallet.owner(), BOB);
        assertEq(wallet.pendingOwner(), address(0));
    }

    function test_transferOwnership_revertsWhen_callerNotOwner() public {
        vm.prank(BOB);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, BOB));
        wallet.transferOwnership(BOB);
    }

    function test_acceptOwnership_revertsWhen_callerNotPendingOwner() public {
        vm.prank(ALICE);
        wallet.transferOwnership(BOB);

        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ADMIN));
        wallet.acceptOwnership();
    }

    function test_renounceOwnership_revertsAlways() public {
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.RenounceDisabled.selector);
        wallet.renounceOwnership();
    }
}
