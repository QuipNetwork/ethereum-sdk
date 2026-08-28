// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_statelessTreeId`: keccak256(pkSeed ‖ hypertreeRoot)
///      over the first 32 bytes of each field.
contract ShrincsWallet__statelessTreeId is ShrincsWalletTest {
    function test_statelessTreeId_hashesSeedAndRoot() public view {
        assertEq(
            wallet.exposed_statelessTreeId(mainPk.pkSeed, mainPk.hypertreeRoot),
            _statelessId(mainPk),
            "keccak256(pkSeed || hypertreeRoot)"
        );
    }

    function test_statelessTreeId_distinctTreesDiffer() public view {
        bytes memory otherRoot = mainPk.hypertreeRoot;
        otherRoot[0] = bytes1(uint8(otherRoot[0]) ^ 0x01);
        assertTrue(
            wallet.exposed_statelessTreeId(mainPk.pkSeed, otherRoot) != _statelessId(mainPk),
            "root change changes identity"
        );
    }

    function test_statelessTreeId_revertsWhen_fieldShorterThan32() public {
        bytes memory short = new bytes(31);
        vm.expectRevert();
        wallet.exposed_statelessTreeId(short, mainPk.hypertreeRoot);
    }
}
