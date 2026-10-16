// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {ShrincsWalletHarness} from "../../../harness/ShrincsWalletHarness.sol";
import {IShrincsWallet} from "../../../../contracts/shrincs/interfaces/IShrincsWallet.sol";

contract ShrincsWalletRecoveryHandler is Test {
    ShrincsWalletHarness internal wallet;
    address internal owner;
    bytes internal recoveryCall;
    bytes internal oldExecuteCall;
    bytes internal oldKeyCurrentContextCall;
    bytes internal newExecuteCall;

    bool public recovered;
    bool public newExecuteLanded;

    function initialize(
        ShrincsWalletHarness wallet_,
        address owner_,
        bytes calldata recoveryCall_,
        bytes calldata oldExecuteCall_,
        bytes calldata oldKeyCurrentContextCall_,
        bytes calldata newExecuteCall_
    ) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
        owner = owner_;
        recoveryCall = recoveryCall_;
        oldExecuteCall = oldExecuteCall_;
        oldKeyCurrentContextCall = oldKeyCurrentContextCall_;
        newExecuteCall = newExecuteCall_;
    }

    function _assertRevertSelector(
        bytes memory result,
        bytes4 expected
    ) internal {
        bytes4 actual;
        if (result.length >= 4) {
            assembly ("memory-safe") {
                actual := mload(add(result, 0x20))
            }
        }
        assertEq(actual, expected, "unexpected rejection reason");
    }

    function fuzzRecover() external {
        vm.prank(owner);
        (bool succeeded, bytes memory result) = address(wallet).call(
            recoveryCall
        );
        if (recovered) {
            assertFalse(succeeded, "recovery replay succeeded");
            _assertRevertSelector(
                result,
                IShrincsWallet.InvalidSignature.selector
            );
        } else {
            assertTrue(succeeded, "fresh recovery failed");
            recovered = true;
        }
    }

    function fuzzOldExecute() external {
        if (!recovered) return;
        vm.prank(owner);
        (bool succeeded, bytes memory result) = address(wallet).call(
            oldExecuteCall
        );
        assertFalse(succeeded, "old-key execute succeeded after recovery");
        _assertRevertSelector(result, IShrincsWallet.InvalidSignature.selector);

        vm.prank(owner);
        (succeeded, result) = address(wallet).call(oldKeyCurrentContextCall);
        assertFalse(succeeded, "old key accepted in recovered context");
        _assertRevertSelector(result, IShrincsWallet.InvalidSignature.selector);
    }

    function fuzzNewExecute() external {
        vm.prank(owner);
        (bool succeeded, bytes memory result) = address(wallet).call(
            newExecuteCall
        );
        if (!recovered || newExecuteLanded) {
            assertFalse(succeeded, "new-key execute succeeded out of order");
            _assertRevertSelector(
                result,
                recovered
                    ? IShrincsWallet.StaleStatefulLeaf.selector
                    : IShrincsWallet.InvalidSignature.selector
            );
        } else {
            assertTrue(succeeded, "new-key execute failed after recovery");
            newExecuteLanded = true;
        }
    }
}
