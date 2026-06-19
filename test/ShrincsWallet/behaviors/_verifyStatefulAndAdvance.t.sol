// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the shared internal `_verifyStatefulAndAdvance` (via the harness). It is
///      the replay-blocking core of every owner-path action: leaf budget/used checks, SHRINCS
///      verify, then the bitmap consume. Reverts, InvalidSignature, and the success consume (driven by the
///      EXECUTE vector) are all exercised.
contract ShrincsWallet__verifyStatefulAndAdvance is ShrincsWalletTest {
    bytes32 internal constant ACTION = keccak256("test.action");
    bytes32 internal constant PAYLOAD = keccak256("test.payload");

    function _pk() internal view returns (ShrincsTypes.PublicKey memory) {
        return _parsePublicKey(".mainKey");
    }

    function test_verifyStatefulAndAdvance_revertsWhen_leafZero() public {
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), _statefulSigWithLeaf(0), ACTION, PAYLOAD);
    }

    function test_verifyStatefulAndAdvance_revertsWhen_leafOverBudget() public {
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1), ACTION, PAYLOAD);
    }

    function test_verifyStatefulAndAdvance_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(1);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), _statefulSigWithLeaf(1), ACTION, PAYLOAD);
    }

    function test_verifyStatefulAndAdvance_revertsWhen_invalidSignature() public {
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), _wrongContextStatefulSig(), ACTION, PAYLOAD);
        assertFalse(wallet.isStatefulLeafUsed(1), "leaf not consumed on invalid signature");
    }

    function test_verifyStatefulAndAdvance_consumesLeafOnSuccess() public {
        // Drive the success path with the EXECUTE vector: its signature is bound to
        // ACTION_EXECUTE over the committed execute payload hash, so it verifies and consumes leaf 1.
        bytes32 actionExecute = keccak256("quip.shrincs.action.execute");
        bytes32 payloadHash = _bytes32(".cases.execute.payloadHash");
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.execute.signature");

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.StatefulSignatureVerified(1, 0);
        uint32 leaf = wallet.exposed_verifyStatefulAndAdvance(_pk(), sig, actionExecute, payloadHash);

        assertEq(leaf, 1, "consumed leaf returned");
        assertTrue(wallet.isStatefulLeafUsed(1), "leaf 1 marked used");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
    }

    /// @dev The consumed leaf tracks the signature, not a hardcoded 1: the `erc4337[1]` vector is a
    ///      leaf-2 signature, so it consumes exactly leaf 2 (and leaf 1 stays unused).
    function test_verifyStatefulAndAdvance_consumesNonInitialLeaf() public {
        bytes32 actionErc4337 = keccak256("quip.shrincs.action.erc4337Execute");
        bytes32 payloadHash = _bytes32(".cases.erc4337[1].payloadHash");
        ShrincsTypes.StatefulSignature memory sig = _parseStatefulSignature(".cases.erc4337[1].signature");

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.StatefulSignatureVerified(2, 0);
        uint32 leaf = wallet.exposed_verifyStatefulAndAdvance(_pk(), sig, actionErc4337, payloadHash);

        assertEq(leaf, 2, "leaf 2 consumed");
        assertTrue(wallet.isStatefulLeafUsed(2), "leaf 2 marked used");
        assertFalse(wallet.isStatefulLeafUsed(1), "leaf 1 untouched");
        assertEq(wallet.statefulLeavesUsed(), 1, "exactly one leaf consumed");
    }

    /* ─────────────────────────────── FUZZ ─────────────────────────────── */

    /// @dev The pre-verify budget guard runs before any crypto, so it is fully fuzzable with a
    ///      synthetic signature whose only meaningful field is `authPath.length` (= the leaf). A
    ///      leaf of 0 or above the budget reverts `StatefulBudgetExhausted`; an in-budget leaf
    ///      reaches `SHRINCS.verifyStateful`, which rejects the empty signature as `InvalidSignature`.
    function testFuzz_verifyStatefulAndAdvance_budgetGuard(uint256 leaf) public {
        leaf = bound(leaf, 0, 512); // `_statefulSigWithLeaf` allocates `new bytes32[](leaf)`
        if (leaf == 0 || leaf > MAX_SIG) {
            vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        } else {
            vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        }
        wallet.exposed_verifyStatefulAndAdvance(_pk(), _statefulSigWithLeaf(leaf), ACTION, PAYLOAD);
        // No path consumes a leaf on failure.
        assertEq(wallet.statefulLeavesUsed(), 0, "no leaf consumed on any reject");
    }

    /// @dev Any in-budget leaf already present in the bitmap is rejected `StaleStatefulLeaf` before
    ///      verification, regardless of which leaf it is.
    function testFuzz_verifyStatefulAndAdvance_replayGuard(uint256 leaf) public {
        leaf = bound(leaf, 1, MAX_SIG);
        wallet.harness_markLeafUsed(uint32(leaf));
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), _statefulSigWithLeaf(leaf), ACTION, PAYLOAD);
    }
}
