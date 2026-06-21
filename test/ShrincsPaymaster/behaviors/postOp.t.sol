// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Vm} from "forge-std-1.14.0/Vm.sol";
import {IPaymaster} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for `postOp` (gas-accounting event emitter; `onlyEntryPoint`).
contract ShrincsPaymaster_postOp is ShrincsPaymasterTest {
    address internal constant WALLET = address(0xB0B);

    function _postOp(
        IPaymaster.PostOpMode mode,
        bytes memory context
    ) internal {
        vm.prank(ENTRY_POINT);
        paymaster.postOp(mode, context, 1234, 5678);
    }

    function test_postOp_emitsUserOpSponsored_succeeded() public {
        vm.recordLogs();
        _postOp(IPaymaster.PostOpMode.opSucceeded, abi.encode(WALLET));
        _assertSponsored(WALLET);
    }

    function test_postOp_emitsUserOpSponsored_opReverted() public {
        vm.recordLogs();
        _postOp(IPaymaster.PostOpMode.opReverted, abi.encode(WALLET));
        _assertSponsored(WALLET);
    }

    function test_postOp_emitsUserOpSponsored_postOpReverted() public {
        vm.recordLogs();
        _postOp(IPaymaster.PostOpMode.postOpReverted, abi.encode(WALLET));
        _assertSponsored(WALLET);
    }

    function _assertSponsored(address wallet) internal {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        for (uint256 i; i < logs.length; i++) {
            if (
                logs[i].topics[0] == IShrincsPaymaster.UserOpSponsored.selector
            ) {
                found = true;
                assertEq(
                    address(uint160(uint256(logs[i].topics[1]))),
                    wallet,
                    "wallet indexed"
                );
                (uint256 gasCost, uint256 feePerGas) = abi.decode(
                    logs[i].data,
                    (uint256, uint256)
                );
                assertEq(gasCost, 1234, "actualGasCost");
                assertEq(feePerGas, 5678, "actualUserOpFeePerGas");
            }
        }
        assertTrue(found, "UserOpSponsored emitted");
    }

    function test_postOp_revertsWhen_notEntryPoint() public {
        vm.prank(makeAddr("stranger"));
        vm.expectRevert(IShrincsPaymaster.InvalidEntryPoint.selector);
        paymaster.postOp(
            IPaymaster.PostOpMode.opSucceeded,
            abi.encode(WALLET),
            1,
            1
        );
    }

    function test_postOp_revertsWhen_emptyContext() public {
        vm.prank(ENTRY_POINT);
        vm.expectRevert();
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, "", 1, 1);
    }
}
