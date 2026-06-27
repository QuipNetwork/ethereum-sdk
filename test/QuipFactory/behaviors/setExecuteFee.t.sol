// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipFactory_setExecuteFee is QuipFactoryTest {
    function test_setExecuteFee_setsFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        assertEq(factory.executeFee(), EXECUTE_FEE);
    }

    function test_setExecuteFee_emitsExecuteFeeUpdated() public {
        vm.prank(ADMIN);
        vm.recordLogs();
        factory.setExecuteFee(EXECUTE_FEE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipFactory.ExecuteFeeUpdated.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "ExecuteFeeUpdated event not emitted");
    }

    function test_setExecuteFee_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(
            abi.encodeWithSelector(
                Ownable.OwnableUnauthorizedAccount.selector,
                ALICE
            )
        );
        factory.setExecuteFee(EXECUTE_FEE);
    }

    function test_setExecuteFee_setsZeroFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);
        assertEq(factory.executeFee(), EXECUTE_FEE);

        vm.prank(ADMIN);
        factory.setExecuteFee(0);
        assertEq(factory.executeFee(), 0);
    }

    function test_setExecuteFee_setsMaxFee() public {
        uint256 maxFee = factory.MAX_FEE();
        vm.prank(ADMIN);
        factory.setExecuteFee(maxFee);
        assertEq(factory.executeFee(), maxFee);
    }

    function test_setExecuteFee_revertsWhen_feeExceedsMax() public {
        uint256 maxFee = factory.MAX_FEE();
        uint256 excessFee = maxFee + 1;
        vm.prank(ADMIN);
        vm.expectRevert(
            abi.encodeWithSelector(
                IQuipFactory.FeeExceedsMax.selector,
                excessFee,
                maxFee
            )
        );
        factory.setExecuteFee(excessFee);
    }
}
