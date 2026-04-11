// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {Ownable as SoladyOwnable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipWallet_transferOwnership is QuipWalletTest {
    function test_transferOwnership_transfersImmediately() public {
        vm.prank(ALICE);
        wallet.transferOwnership(BOB);

        assertEq(wallet.owner(), BOB);
    }

    function test_transferOwnership_completesHandover() public {
        vm.prank(BOB);
        wallet.requestOwnershipHandover();

        vm.prank(ALICE);
        wallet.completeOwnershipHandover(BOB);

        assertEq(wallet.owner(), BOB);
    }

    function test_transferOwnership_revertsWhen_callerNotOwner() public {
        vm.prank(BOB);
        vm.expectRevert(SoladyOwnable.Unauthorized.selector);
        wallet.transferOwnership(BOB);
    }

    function test_transferOwnership_revertsWhen_noHandoverRequest() public {
        vm.prank(ALICE);
        vm.expectRevert(SoladyOwnable.NoHandoverRequest.selector);
        wallet.completeOwnershipHandover(BOB);
    }
}
