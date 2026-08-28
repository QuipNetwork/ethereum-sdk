// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_statefulTreeId`: keccak256(pkSeed ‖ root) of a decoded
///      68-byte stateful key. The trailing `maxSignatures` is deliberately excluded so a
///      re-declared budget cannot mint a "new" identity for the same tree.
contract ShrincsWallet__statefulTreeId is ShrincsWalletTest {
    function test_statefulTreeId_hashesSeedAndRoot() public view {
        assertEq(
            wallet.exposed_statefulTreeId(mainPk.statefulPublicKey),
            _treeId(mainPk.statefulPublicKey),
            "keccak256(pkSeed || root)"
        );
    }

    function test_statefulTreeId_ignoresMaxSignatures() public view {
        bytes memory spk = mainPk.statefulPublicKey;
        spk[67] = bytes1(uint8(spk[67]) + 1);
        assertEq(
            wallet.exposed_statefulTreeId(spk),
            wallet.exposed_statefulTreeId(mainPk.statefulPublicKey),
            "budget does not change identity"
        );
    }

    function test_statefulTreeId_distinctTreesDiffer() public view {
        bytes memory spk = mainPk.statefulPublicKey;
        spk[40] = bytes1(uint8(spk[40]) ^ 0x01); // inside `root`
        bytes32 installed = wallet.exposed_statefulTreeId(mainPk.statefulPublicKey);
        assertTrue(wallet.exposed_statefulTreeId(spk) != installed, "root change changes identity");
    }

    function test_statefulTreeId_revertsWhen_malformedKey() public {
        bytes memory bad = new bytes(67);
        vm.expectRevert(IShrincsWallet.CommitmentMismatch.selector);
        wallet.exposed_statefulTreeId(bad);
    }
}
