// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryTest} from "../QuipFactory.t.sol";
import {Ownable} from "@openzeppelin-contracts-5.6.0-rc.1/access/Ownable.sol";
import {IQuipFactory} from "../../../contracts/interfaces/IQuipFactory.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";

contract QuipFactory_setTransferFee is QuipFactoryTest {
    function test_setTransferFee_setsFee() public {
        vm.prank(ADMIN);
        factory.setTransferFee(TRANSFER_FEE);

        assertEq(factory.transferFee(), TRANSFER_FEE);
    }

    function test_setTransferFee_emitsTransferFeeUpdated() public {
        vm.prank(ADMIN);
        vm.recordLogs();
        factory.setTransferFee(TRANSFER_FEE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IQuipFactory.TransferFeeUpdated.selector) {
                found = true;
                break;
            }
        }
        assertTrue(found, "TransferFeeUpdated event not emitted");
    }

    function test_setTransferFee_revertsWhen_callerNotAdmin() public {
        vm.prank(ALICE);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, ALICE));
        factory.setTransferFee(TRANSFER_FEE);
    }

    function test_setTransferFee_setsZeroFee() public {
        vm.prank(ADMIN);
        factory.setTransferFee(TRANSFER_FEE);
        assertEq(factory.transferFee(), TRANSFER_FEE);

        vm.prank(ADMIN);
        factory.setTransferFee(0);
        assertEq(factory.transferFee(), 0);
    }

    function test_setTransferFee_setsMaxFee() public {
        uint256 maxFee = factory.MAX_FEE();
        vm.prank(ADMIN);
        factory.setTransferFee(maxFee);
        assertEq(factory.transferFee(), maxFee);
    }

    function test_setTransferFee_revertsWhen_feeExceedsMax() public {
        uint256 maxFee = factory.MAX_FEE();
        uint256 excessFee = maxFee + 1;
        vm.prank(ADMIN);
        vm.expectRevert(abi.encodeWithSelector(IQuipFactory.FeeExceedsMax.selector, excessFee, maxFee));
        factory.setTransferFee(excessFee);
    }
}
