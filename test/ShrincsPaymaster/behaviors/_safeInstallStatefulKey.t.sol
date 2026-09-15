// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsPaymaster} from "../../../contracts/interfaces/IShrincsPaymaster.sol";
import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Behavior tests for the internal `_safeInstallStatefulKey` check-and-record primitive: a
///      stateful key's tree is recorded once for the paymaster's lifetime and any repeat is refused.
contract ShrincsPaymaster__safeInstallStatefulKey is ShrincsPaymasterTest {
    /// @dev A synthetic (but decodable) 68-byte stateful public-key encoding.
    function _spk(bytes32 seed, bytes32 root) internal pure returns (bytes memory) {
        return abi.encodePacked(seed, root, uint32(8));
    }

    function test_safeInstallStatefulKey_recordsTree() public {
        bytes memory spk = _spk(keccak256("fresh-seed"), keccak256("fresh-root"));
        bytes32 id = _treeId(spk);
        assertFalse(paymaster.harness_isStatefulTreeSpent(id), "unspent before");
        paymaster.exposed_safeInstallStatefulKey(spk);
        assertTrue(paymaster.harness_isStatefulTreeSpent(id), "spent after");
    }

    function test_safeInstallStatefulKey_isPerTree() public {
        paymaster.exposed_safeInstallStatefulKey(_spk(keccak256("a-seed"), keccak256("a-root")));
        assertFalse(paymaster.harness_isStatefulTreeSpent(keccak256("other")), "other ids untouched");
    }

    function test_safeInstallStatefulKey_revertsWhen_alreadyInstalled() public {
        bytes memory spk = _spk(keccak256("b-seed"), keccak256("b-root"));
        paymaster.exposed_safeInstallStatefulKey(spk);
        vm.expectRevert(abi.encodeWithSelector(IShrincsPaymaster.StatefulTreeSpent.selector, _treeId(spk)));
        paymaster.exposed_safeInstallStatefulKey(spk);
    }

    function test_safeInstallStatefulKey_revertsWhen_installedVerifierKey() public {
        bytes32 id = _treeId(verifierPk.statefulPublicKey);
        vm.expectRevert(abi.encodeWithSelector(IShrincsPaymaster.StatefulTreeSpent.selector, id));
        paymaster.exposed_safeInstallStatefulKey(verifierPk.statefulPublicKey);
    }

    function test_safeInstallStatefulKey_revertsWhen_malformedEncoding() public {
        vm.expectRevert(IShrincsPaymaster.CommitmentMismatch.selector);
        paymaster.exposed_safeInstallStatefulKey(hex"deadbeef");
    }
}
