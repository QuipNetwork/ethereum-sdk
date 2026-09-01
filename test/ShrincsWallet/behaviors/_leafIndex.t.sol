// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Unit tests for `_leafIndex` (via `exposed_leafIndex`), the single derivation point every
///      stateful verify path uses: the revealed leaf IS the signature's authentication-path
///      length. The budget guards downstream (`leaf == 0`, `leaf > maxSignatures`) key off this
///      value, so its identity with `authPath.length` is load-bearing.
contract ShrincsWallet__leafIndex is ShrincsWalletTest {
    function test_exposed_leafIndex_returnsAuthPathLength() public view {
        assertEq(wallet.exposed_leafIndex(_statefulSigWithLeaf(7)), 7, "leaf = authPath length");
    }

    function test_exposed_leafIndex_emptyAuthPathIsZero() public view {
        SHRINCS.Signature memory sig; // authPath.length == 0
        assertEq(wallet.exposed_leafIndex(sig), 0, "empty path derives leaf 0 (budget-guard bait)");
    }

    function test_exposed_leafIndex_realSignatureMatchesSigningLeaf() public view {
        // A REAL signature produced at slot 3 reveals exactly leaf SIGN_BASE + 3.
        SHRINCS.Signature memory sig =
            _signStatefulAction(keccak256("leaf-index-action"), keccak256("leaf-index-payload"), 3);
        assertEq(wallet.exposed_leafIndex(sig), SIGN_BASE + 3, "real signature's revealed leaf");
    }

    function testFuzz_exposed_leafIndex_matchesLength(uint256 leaf) public view {
        leaf = bound(leaf, 0, 1024); // `_statefulSigWithLeaf` allocates `new bytes32[](leaf)`
        assertEq(wallet.exposed_leafIndex(_statefulSigWithLeaf(leaf)), leaf, "identity over lengths");
    }
}
