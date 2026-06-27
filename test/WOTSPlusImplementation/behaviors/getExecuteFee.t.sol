// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";

contract WOTSPlusImplementation_getExecuteFee is WOTSPlusImplementationTest {
    function test_getExecuteFee_returnsZeroWhenFactoryFeeIsZero() public view {
        assertEq(wallet.getExecuteFee(), 0);
    }

    function test_getExecuteFee_returnsCorrectValueAfterFactoryFeeChange() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        assertEq(wallet.getExecuteFee(), EXECUTE_FEE);
    }

    function test_getExecuteFee_reflectsMultipleFeeUpdates() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);
        assertEq(wallet.getExecuteFee(), EXECUTE_FEE);

        uint256 newFee = 0.005 ether;
        vm.prank(ADMIN);
        factory.setExecuteFee(newFee);
        assertEq(wallet.getExecuteFee(), newFee);
    }
}
