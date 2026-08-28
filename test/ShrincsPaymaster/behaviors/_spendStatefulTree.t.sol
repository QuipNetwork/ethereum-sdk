// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the internal `_spendStatefulTree` check-and-record primitive: a tree
///      id is recorded once for the paymaster's lifetime and any repeat is refused.
contract ShrincsPaymaster__spendStatefulTree is ShrincsPaymasterTest {
    bytes32 internal constant TREE = keccak256("fresh-stateful-tree");

    function test_spendStatefulTree_recordsTree() public {
        assertFalse(paymaster.harness_isStatefulTreeSpent(TREE), "unspent before");
        paymaster.exposed_spendStatefulTree(TREE);
        assertTrue(paymaster.harness_isStatefulTreeSpent(TREE), "spent after");
    }

    function test_spendStatefulTree_isPerTree() public {
        paymaster.exposed_spendStatefulTree(TREE);
        assertFalse(paymaster.harness_isStatefulTreeSpent(keccak256("other")), "other ids untouched");
    }

    function test_spendStatefulTree_revertsWhen_alreadySpent() public {
        paymaster.exposed_spendStatefulTree(TREE);
        vm.expectRevert(abi.encodeWithSelector(IShrincsPaymaster.StatefulTreeSpent.selector, TREE));
        paymaster.exposed_spendStatefulTree(TREE);
    }

    function test_spendStatefulTree_revertsWhen_installedTree() public {
        bytes32 id = _treeId(verifierPk.statefulPublicKey);
        vm.expectRevert(abi.encodeWithSelector(IShrincsPaymaster.StatefulTreeSpent.selector, id));
        paymaster.exposed_spendStatefulTree(id);
    }
}
