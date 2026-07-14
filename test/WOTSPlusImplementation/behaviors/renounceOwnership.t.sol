// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {IWOTSPlusImplementation} from "../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";

contract WOTSPlusImplementation_renounceOwnership is WOTSPlusImplementationTest {
    function test_renounceOwnership_alwaysReverts() public {
        vm.prank(ALICE);
        vm.expectRevert(IWOTSPlusImplementation.RenounceDisabled.selector);
        wallet.renounceOwnership();
    }
}
