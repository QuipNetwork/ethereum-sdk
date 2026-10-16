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
        // Calldata slice `pkSeed[:32]` on a 31-byte field reverts with empty returndata
        // (Solidity sliceOutOfBounds — no custom error / Panic selector to pin).
        vm.expectRevert();
        wallet.exposed_statelessTreeId(short, mainPk.hypertreeRoot);
    }

    /// @dev Shared SDK↔contract vector. The same constants are asserted in
    ///      `src/v1/shrincs/tests/shrincsCodec.test.ts` so SDK and contract can never drift silently.
    function test_statelessTreeId_matchesSharedSdkVector() public view {
        bytes memory pkSeed = hex"1111111111111111111111111111111111111111111111111111111111111111";
        bytes memory hypertreeRoot = hex"2222222222222222222222222222222222222222222222222222222222222222";
        assertEq(
            wallet.exposed_statelessTreeId(pkSeed, hypertreeRoot),
            bytes32(0x3e92e0db88d6afea9edc4eedf62fffa4d92bcdfc310dccbe943747fe8302e871)
        );
    }
}
