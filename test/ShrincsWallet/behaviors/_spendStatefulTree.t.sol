// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_spendStatefulTree` check-and-record primitive: a tree
///      id is recorded once for the wallet's lifetime and any repeat is refused.
contract ShrincsWallet__spendStatefulTree is ShrincsWalletTest {
    bytes32 internal constant TREE = keccak256("fresh-stateful-tree");

    function test_spendStatefulTree_recordsTree() public {
        assertFalse(wallet.harness_isStatefulTreeSpent(TREE), "unspent before");
        wallet.exposed_spendStatefulTree(TREE);
        assertTrue(wallet.harness_isStatefulTreeSpent(TREE), "spent after");
    }

    function test_spendStatefulTree_isPerTree() public {
        wallet.exposed_spendStatefulTree(TREE);
        assertFalse(wallet.harness_isStatefulTreeSpent(keccak256("other")), "other ids untouched");
    }

    function test_spendStatefulTree_doesNotTouchStatelessRegistry() public {
        wallet.exposed_spendStatefulTree(TREE);
        assertFalse(wallet.harness_isStatelessTreeSpent(TREE), "namespaces are independent");
    }

    function test_spendStatefulTree_revertsWhen_alreadySpent() public {
        wallet.exposed_spendStatefulTree(TREE);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, TREE));
        wallet.exposed_spendStatefulTree(TREE);
    }

    function test_spendStatefulTree_revertsWhen_installedTree() public {
        bytes32 id = _treeId(mainPk.statefulPublicKey);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, id));
        wallet.exposed_spendStatefulTree(id);
    }
}
