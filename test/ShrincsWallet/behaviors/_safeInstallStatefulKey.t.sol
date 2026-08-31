// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_safeInstallStatefulKey` check-and-record primitive: a
///      stateful key's tree is recorded once for the wallet's lifetime and any repeat is refused.
contract ShrincsWallet__safeInstallStatefulKey is ShrincsWalletTest {
    /// @dev A synthetic (but decodable) 68-byte stateful public-key encoding.
    function _spk(bytes32 seed, bytes32 root) internal pure returns (bytes memory) {
        return abi.encodePacked(seed, root, uint32(8));
    }

    function test_safeInstallStatefulKey_recordsTree() public {
        bytes memory spk = _spk(keccak256("fresh-seed"), keccak256("fresh-root"));
        bytes32 id = _treeId(spk);
        assertFalse(wallet.harness_isStatefulTreeSpent(id), "unspent before");
        wallet.exposed_safeInstallStatefulKey(spk);
        assertTrue(wallet.harness_isStatefulTreeSpent(id), "spent after");
    }

    function test_safeInstallStatefulKey_isPerTree() public {
        wallet.exposed_safeInstallStatefulKey(_spk(keccak256("a-seed"), keccak256("a-root")));
        assertFalse(wallet.harness_isStatefulTreeSpent(keccak256("other")), "other ids untouched");
    }

    function test_safeInstallStatefulKey_doesNotTouchStatelessRegistry() public {
        bytes memory spk = _spk(keccak256("b-seed"), keccak256("b-root"));
        wallet.exposed_safeInstallStatefulKey(spk);
        assertFalse(wallet.harness_isStatelessTreeSpent(_treeId(spk)), "namespaces are independent");
    }

    function test_safeInstallStatefulKey_revertsWhen_sameTreeDifferentBudget() public {
        // Same tree under a different maxSignatures is the same tree (identity excludes budget).
        wallet.exposed_safeInstallStatefulKey(abi.encodePacked(keccak256("c-seed"), keccak256("c-root"), uint32(8)));
        bytes memory rebudgeted = abi.encodePacked(keccak256("c-seed"), keccak256("c-root"), uint32(9));
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(rebudgeted)));
        wallet.exposed_safeInstallStatefulKey(rebudgeted);
    }

    function test_safeInstallStatefulKey_revertsWhen_alreadyInstalled() public {
        bytes memory spk = _spk(keccak256("d-seed"), keccak256("d-root"));
        wallet.exposed_safeInstallStatefulKey(spk);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, _treeId(spk)));
        wallet.exposed_safeInstallStatefulKey(spk);
    }

    function test_safeInstallStatefulKey_revertsWhen_walletsInstalledKey() public {
        bytes32 id = _treeId(mainPk.statefulPublicKey);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatefulTreeSpent.selector, id));
        wallet.exposed_safeInstallStatefulKey(mainPk.statefulPublicKey);
    }

    function test_safeInstallStatefulKey_revertsWhen_malformedEncoding() public {
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.exposed_safeInstallStatefulKey(hex"deadbeef");
    }
}
