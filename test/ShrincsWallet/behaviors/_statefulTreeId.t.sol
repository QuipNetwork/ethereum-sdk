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

    /// @dev Shared SDK↔contract vector: byte i of the 68-byte key is `i`; identity hashes
    ///      pkSeed ‖ root only (bytes 0..63). The same constants are asserted in
    ///      `src/v1/shrincs/tests/shrincsCodec.test.ts` so SDK and contract can never drift silently.
    function test_statefulTreeId_matchesSharedSdkVector() public view {
        bytes memory spk =
            hex"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243";
        assertEq(
            wallet.exposed_statefulTreeId(spk),
            bytes32(0x002030bde3d4cf89919649775cd71875c4d0ab1708a380e03fefc3a28aa24831)
        );
    }
}
