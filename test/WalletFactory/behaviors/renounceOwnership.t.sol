// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {IWalletFactory} from "../../../contracts/interfaces/IWalletFactory.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract WalletFactory_renounceOwnership is WalletFactoryTest {
    function test_renounceOwnership_revertsWhen_calledByOwner() public {
        vm.prank(ADMIN);
        vm.expectRevert(IWalletFactory.RenounceDisabled.selector);
        factory.renounceOwnership();
    }

    function test_renounceOwnership_revertsWhen_calledByNonOwner() public {
        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        factory.renounceOwnership();
    }
}
