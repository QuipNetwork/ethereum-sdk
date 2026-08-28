// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_spendStatelessTree` check-and-record primitive: a tree
///      id is recorded once for the wallet's lifetime and any repeat is refused.
contract ShrincsWallet__spendStatelessTree is ShrincsWalletTest {
    bytes32 internal constant TREE = keccak256("fresh-stateless-tree");

    function test_spendStatelessTree_recordsTree() public {
        assertFalse(wallet.harness_isStatelessTreeSpent(TREE), "unspent before");
        wallet.exposed_spendStatelessTree(TREE);
        assertTrue(wallet.harness_isStatelessTreeSpent(TREE), "spent after");
    }

    function test_spendStatelessTree_isPerTree() public {
        wallet.exposed_spendStatelessTree(TREE);
        assertFalse(wallet.harness_isStatelessTreeSpent(keccak256("other")), "other ids untouched");
    }

    function test_spendStatelessTree_doesNotTouchStatefulRegistry() public {
        wallet.exposed_spendStatelessTree(TREE);
        assertFalse(wallet.harness_isStatefulTreeSpent(TREE), "namespaces are independent");
    }

    function test_spendStatelessTree_revertsWhen_alreadySpent() public {
        wallet.exposed_spendStatelessTree(TREE);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, TREE));
        wallet.exposed_spendStatelessTree(TREE);
    }

    function test_spendStatelessTree_revertsWhen_installedTree() public {
        bytes32 id = _statelessId(mainPk);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, id));
        wallet.exposed_spendStatelessTree(id);
    }
}
