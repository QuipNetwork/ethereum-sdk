// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
// prettier-ignore
import {
    IERC7913SignatureVerifier
} from "@quip.network/hashsigs-solidity-0.2.0/contracts/interfaces/IERC7913SignatureVerifier.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the shared internal `_verifyStatefulAndAdvance` (via the harness). It is
///      the replay-blocking core of every owner-path action: leaf budget/used checks, SHRINCS
///      verify over the live-nonce context, then the bitmap consume + nonce advance. Reverts,
///      InvalidSignature (including stale-nonce supersession), and the success consume (driven
///      by live-signed EXECUTE / ERC-4337 signatures) are all exercised.
contract ShrincsWallet__verifyStatefulAndAdvance is ShrincsWalletTest {
    bytes32 internal constant ACTION = keccak256("test.action");
    bytes32 internal constant PAYLOAD = keccak256("test.payload");

    function _pk() internal view returns (SHRINCS.PublicKey memory) {
        return _mainPk();
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
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), _statefulSigWithLeaf(SIGN_BASE + 1), ACTION, PAYLOAD);
    }

    function test_verifyStatefulAndAdvance_revertsWhen_invalidSignature() public {
        SHRINCS.Signature memory sig = _wrongContextStatefulSig();
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), sig, ACTION, PAYLOAD);
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed on invalid signature");
    }

    function test_verifyStatefulAndAdvance_consumesLeafOnSuccess() public {
        // Drive the success path with a live EXECUTE signature bound to ACTION_EXECUTE over an
        // arbitrary payload hash, so it verifies and consumes leaf 1.
        bytes32 payloadHash = keccak256("execute-payload");
        SHRINCS.Signature memory sig = _signStatefulAction(Codec.ACTION_EXECUTE, payloadHash, 1);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.StatefulSignatureVerified(SIGN_BASE + 1, 0);
        uint32 leaf = wallet.exposed_verifyStatefulAndAdvance(_pk(), sig, Codec.ACTION_EXECUTE, payloadHash);

        assertEq(leaf, SIGN_BASE + 1, "consumed leaf returned");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 marked used");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
        assertEq(wallet.actionNonce(), 1, "consumed signature advances the action nonce");
    }

    /// @dev Every success advances the nonce by exactly one; no revert branch touches it
    ///      (the revert cases above roll back state, so only assert the success arithmetic here).
    function test_verifyStatefulAndAdvance_advancesNoncePerSignature() public {
        bytes32 p1 = keccak256("payload-1");
        SHRINCS.Signature memory s1 = _signStatefulAction(Codec.ACTION_EXECUTE, p1, 1);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), s1, Codec.ACTION_EXECUTE, p1);
        assertEq(wallet.actionNonce(), 1, "+1 after first consume");

        // The second signature must bind the NEW live nonce (signed after the first landed).
        bytes32 p2 = keccak256("payload-2");
        SHRINCS.Signature memory s2 = _signStatefulAction(Codec.ACTION_EXECUTE, p2, 2);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), s2, Codec.ACTION_EXECUTE, p2);
        assertEq(wallet.actionNonce(), 2, "+1 after second consume");
    }

    /// @dev A signature bound to a superseded nonce is rejected `InvalidSignature` with no state
    ///      change — the supersession property that replaced the signed-deadline design.
    function test_verifyStatefulAndAdvance_rejectsStaleNonce() public {
        bytes32 payloadHash = keccak256("stale-nonce-payload");
        SHRINCS.Signature memory sig = _signStatefulAction(Codec.ACTION_EXECUTE, payloadHash, 1);

        // Any consumed signature elsewhere advances the live nonce past the one `sig` binds.
        wallet.harness_setNonce(wallet.actionNonce() + 1);

        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), sig, Codec.ACTION_EXECUTE, payloadHash);
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed on stale nonce");
        assertEq(wallet.statefulLeavesUsed(), 0, "counter untouched");
    }

    /// @dev The consumed leaf tracks the signature, not a hardcoded 1: a leaf-2 signature consumes
    ///      exactly leaf 2 (and leaf 1 stays unused).
    function test_verifyStatefulAndAdvance_consumesNonInitialLeaf() public {
        bytes32 payloadHash = keccak256("erc4337-payload");
        SHRINCS.Signature memory sig = _signStatefulAction(Codec.ACTION_ERC4337_EXECUTE, payloadHash, 2);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.StatefulSignatureVerified(SIGN_BASE + 2, 0);
        uint32 leaf = wallet.exposed_verifyStatefulAndAdvance(_pk(), sig, Codec.ACTION_ERC4337_EXECUTE, payloadHash);

        assertEq(leaf, SIGN_BASE + 2, "leaf 2 consumed");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 2), "leaf 2 marked used");
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 untouched");
        assertEq(wallet.statefulLeavesUsed(), 1, "exactly one leaf consumed");
    }

    /* ────────────────────── EXTERNAL VERIFIER DELEGATION ────────────────────── */

    /// @dev The stateful verify must actually leave the wallet: a consumed action staticcalls
    ///      the pinned verifier's ERC-7913 `verify`.
    function test_verifyStatefulAndAdvance_delegatesToVerifier() public {
        bytes32 payloadHash = keccak256("external-verifier-stateful-probe");
        SHRINCS.Signature memory sig = _signStatefulAction(Codec.ACTION_EXECUTE, payloadHash, 1);
        vm.expectCall(
            address(shrincsVerifier), abi.encodeWithSelector(IERC7913SignatureVerifier.verify.selector)
        );
        uint32 leaf = wallet.exposed_verifyStatefulAndAdvance(_pk(), sig, Codec.ACTION_EXECUTE, payloadHash);
        assertEq(leaf, SIGN_BASE + 1, "leaf consumed through the external verifier");
    }

    /// @dev Nothing verifies in-wallet anymore: with the verifier's code stripped, even a VALID
    ///      signature cannot be accepted. The failure is a loud revert (solc's return-data check
    ///      on the codeless call raises a decoding error, which try/catch deliberately does not
    ///      swallow) — a missing verifier must never be misread as a mere invalid signature.
    function test_verifyStatefulAndAdvance_revertsWhen_verifierCodeRemoved() public {
        bytes32 payloadHash = keccak256("external-verifier-empty-code-probe");
        SHRINCS.Signature memory sig = _signStatefulAction(Codec.ACTION_EXECUTE, payloadHash, 1);
        vm.etch(address(shrincsVerifier), "");
        vm.expectRevert();
        wallet.exposed_verifyStatefulAndAdvance(_pk(), sig, Codec.ACTION_EXECUTE, payloadHash);
    }

    /* ────────────────────── CONSUME VARIANT (no nonce advance) ────────────────────── */

    /// @dev `_verifyStatefulAndConsume` is the `markLeavesUsed` carve-out: identical verify +
    ///      bitmap consume + counter + event, but the action nonce must stay untouched.
    function test_verifyStatefulAndConsume_doesNotAdvanceNonce() public {
        bytes32 payloadHash = keccak256("consume-payload");
        SHRINCS.Signature memory sig =
            _signStatefulAction(Codec.ACTION_MARK_LEAVES_USED, payloadHash, 1);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.StatefulSignatureVerified(SIGN_BASE + 1, 0);
        uint32 leaf =
            wallet.exposed_verifyStatefulAndConsume(_pk(), sig, Codec.ACTION_MARK_LEAVES_USED, payloadHash);

        assertEq(leaf, SIGN_BASE + 1, "consumed leaf returned");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 marked used");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
        assertEq(wallet.actionNonce(), 0, "consume variant must NOT advance the action nonce");
    }

    /// @dev The surgical property at helper level: a signature outstanding when a consume-only
    ///      verification lands still binds the live nonce, so it remains valid — unlike after
    ///      an advance, which supersedes it.
    function test_verifyStatefulAndConsume_preservesOutstandingSignatures() public {
        bytes32 p1 = keccak256("consumed-first");
        bytes32 p2 = keccak256("outstanding");
        // Both signed against the SAME live nonce (0), before either lands.
        SHRINCS.Signature memory s1 =
            _signStatefulAction(Codec.ACTION_MARK_LEAVES_USED, p1, 1);
        SHRINCS.Signature memory s2 = _signStatefulAction(Codec.ACTION_EXECUTE, p2, 2);

        wallet.exposed_verifyStatefulAndConsume(_pk(), s1, Codec.ACTION_MARK_LEAVES_USED, p1);
        // The outstanding signature still verifies: the consume did not supersede it.
        wallet.exposed_verifyStatefulAndAdvance(_pk(), s2, Codec.ACTION_EXECUTE, p2);
        assertEq(wallet.actionNonce(), 1, "only the advancing consume moved the nonce");
        assertEq(wallet.statefulLeavesUsed(), 2, "both leaves consumed");
    }

    /// @dev Contrast pin: after an ADVANCING consume, a same-nonce outstanding signature is
    ///      superseded (`InvalidSignature`) — the exact behavior the consume variant carves out.
    function test_verifyStatefulAndAdvance_supersedesOutstandingSignatures() public {
        bytes32 p1 = keccak256("landed-first");
        bytes32 p2 = keccak256("superseded");
        SHRINCS.Signature memory s1 = _signStatefulAction(Codec.ACTION_EXECUTE, p1, 1);
        SHRINCS.Signature memory s2 = _signStatefulAction(Codec.ACTION_EXECUTE, p2, 2);

        wallet.exposed_verifyStatefulAndAdvance(_pk(), s1, Codec.ACTION_EXECUTE, p1);
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), s2, Codec.ACTION_EXECUTE, p2);
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
        leaf = bound(leaf, SIGN_BASE + 1, MAX_SIG);
        wallet.harness_markLeafUsed(uint32(leaf));
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.exposed_verifyStatefulAndAdvance(_pk(), _statefulSigWithLeaf(leaf), ACTION, PAYLOAD);
    }
}
