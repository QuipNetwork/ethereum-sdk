// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {IQuipWallet} from "../../../contracts/interfaces/IQuipWallet.sol";

contract QuipWallet_renounceOwnership is QuipWalletTest {
    function test_renounceOwnership_alwaysReverts() public {
        vm.prank(ALICE);
        vm.expectRevert(IQuipWallet.RenounceDisabled.selector);
        wallet.renounceOwnership();
    }
}
