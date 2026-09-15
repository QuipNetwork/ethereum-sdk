// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_safeInstallStatelessKey` check-and-record primitive: a
///      stateless key's tree is recorded once for the wallet's lifetime and any repeat is refused.
contract ShrincsWallet__safeInstallStatelessKey is ShrincsWalletTest {
    function _id(bytes memory seed, bytes memory root) internal pure returns (bytes32) {
        return keccak256(bytes.concat(seed, root));
    }

    function _b(bytes32 word) internal pure returns (bytes memory) {
        return abi.encodePacked(word);
    }

    function test_safeInstallStatelessKey_recordsTree() public {
        bytes memory seed = _b(keccak256("fresh-seed"));
        bytes memory root = _b(keccak256("fresh-root"));
        assertFalse(wallet.harness_isStatelessTreeSpent(_id(seed, root)), "unspent before");
        wallet.exposed_safeInstallStatelessKey(seed, root);
        assertTrue(wallet.harness_isStatelessTreeSpent(_id(seed, root)), "spent after");
    }

    function test_safeInstallStatelessKey_isPerTree() public {
        wallet.exposed_safeInstallStatelessKey(_b(keccak256("a-seed")), _b(keccak256("a-root")));
        assertFalse(wallet.harness_isStatelessTreeSpent(keccak256("other")), "other ids untouched");
    }

    function test_safeInstallStatelessKey_doesNotTouchStatefulRegistry() public {
        bytes memory seed = _b(keccak256("b-seed"));
        bytes memory root = _b(keccak256("b-root"));
        wallet.exposed_safeInstallStatelessKey(seed, root);
        assertFalse(wallet.harness_isStatefulTreeSpent(_id(seed, root)), "namespaces are independent");
    }

    function test_safeInstallStatelessKey_revertsWhen_alreadyInstalled() public {
        bytes memory seed = _b(keccak256("c-seed"));
        bytes memory root = _b(keccak256("c-root"));
        wallet.exposed_safeInstallStatelessKey(seed, root);
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _id(seed, root)));
        wallet.exposed_safeInstallStatelessKey(seed, root);
    }

    function test_safeInstallStatelessKey_revertsWhen_walletsRecoveryRoot() public {
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(mainPk)));
        wallet.exposed_safeInstallStatelessKey(mainPk.pkSeed, mainPk.hypertreeRoot);
    }

    function test_safeInstallStatelessKey_revertsWhen_walletsErc1271Root() public {
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.StatelessTreeSpent.selector, _statelessId(erc1271Pk)));
        wallet.exposed_safeInstallStatelessKey(erc1271Pk.pkSeed, erc1271Pk.hypertreeRoot);
    }
}
