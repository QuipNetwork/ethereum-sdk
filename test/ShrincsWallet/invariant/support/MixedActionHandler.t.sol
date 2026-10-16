// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {IShrincsWallet} from "../../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../../harness/ShrincsWalletHarness.sol";

contract ShrincsWalletMixedActionHandler is Test {
    struct SignedAction {
        bytes callData;
        bool isValidation;
    }

    struct SignedRevocation {
        bytes callData;
        uint256 requiredActionCount;
        bool succeeded;
    }

    ShrincsWalletHarness internal wallet;
    address internal owner;
    SignedAction[] internal actions;
    SignedRevocation[] internal revocations;

    uint256 public successfulActions;
    uint256 public unexpectedOutcomes;

    function initialize(ShrincsWalletHarness wallet_, address owner_) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
        owner = owner_;
    }

    function addAction(bytes calldata callData, bool isValidation) external {
        actions.push(
            SignedAction({callData: callData, isValidation: isValidation})
        );
    }

    function addRevocation(
        bytes calldata callData,
        uint256 requiredActionCount
    ) external {
        revocations.push(
            SignedRevocation({
                callData: callData,
                requiredActionCount: requiredActionCount,
                succeeded: false
            })
        );
    }

    function actionCount() external view returns (uint256) {
        return actions.length;
    }

    function revocationSucceeded(uint256 index) external view returns (bool) {
        return revocations[index].succeeded;
    }

    function _isSignatureRejection(
        bytes memory result
    ) internal pure returns (bool) {
        if (result.length < 4) return false;
        bytes4 selector;
        assembly ("memory-safe") {
            selector := mload(add(result, 0x20))
        }
        return
            selector == IShrincsWallet.InvalidSignature.selector ||
            selector == IShrincsWallet.StaleStatefulLeaf.selector;
    }

    function _hasValidationRejection() internal returns (bool) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length == 0) continue;
            if (
                logs[i].topics[0] !=
                IShrincsWallet.UserOpValidationRejected.selector
            ) continue;
            uint256 reason = uint256(logs[i].topics[1]);
            return
                reason ==
                uint256(
                    IShrincsWallet.UserOpValidationFailure.InvalidSignature
                ) ||
                reason ==
                uint256(
                    IShrincsWallet.UserOpValidationFailure.StaleStatefulLeaf
                );
        }
        return false;
    }

    function fuzzReplayAction(uint256 index) external {
        if (actions.length == 0) return;
        index = bound(index, 0, actions.length - 1);
        SignedAction storage action = actions[index];

        if (action.isValidation) vm.recordLogs();
        vm.prank(owner);
        (bool callSucceeded, bytes memory result) = address(wallet).call(
            action.callData
        );
        bool expectedSuccess = index == successfulActions;
        if (action.isValidation) {
            if (!callSucceeded || result.length != 32) {
                unexpectedOutcomes++;
                return;
            }
            uint256 validationResult = abi.decode(result, (uint256));
            if (expectedSuccess) {
                if (validationResult == 0) successfulActions++;
                else unexpectedOutcomes++;
            } else if (validationResult != 1 || !_hasValidationRejection()) {
                unexpectedOutcomes++;
            }
            return;
        }

        if (expectedSuccess) {
            if (callSucceeded) {
                successfulActions++;
            } else {
                unexpectedOutcomes++;
            }
        } else if (callSucceeded || !_isSignatureRejection(result)) {
            unexpectedOutcomes++;
        }
    }

    function fuzzReplayRevocation(uint256 index) external {
        if (revocations.length == 0) return;
        index = bound(index, 0, revocations.length - 1);
        SignedRevocation storage revocation = revocations[index];
        bool shouldSucceed = successfulActions ==
            revocation.requiredActionCount &&
            !revocation.succeeded;

        vm.prank(owner);
        (bool succeeded, bytes memory result) = address(wallet).call(
            revocation.callData
        );
        if (succeeded == shouldSucceed) {
            if (succeeded) revocation.succeeded = true;
            else if (!_isSignatureRejection(result)) unexpectedOutcomes++;
        } else {
            unexpectedOutcomes++;
        }
    }
}
