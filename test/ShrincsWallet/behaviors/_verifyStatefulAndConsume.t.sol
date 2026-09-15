// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {ShrincsWalletCodec as Codec} from "../../../contracts/shrincs/ShrincsWalletCodec.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Unit tests for `_verifyStatefulAndConsume` (via `exposed_verifyStatefulAndConsume`), the
///      guard-carrying core the advancing wrapper delegates to: leaf budget/used checks, SHRINCS
///      verify over the live-nonce context, bitmap consume + counter + event — WITHOUT the
///      action-nonce advance (the `markLeavesUsed` carve-out).
contract ShrincsWallet__verifyStatefulAndConsume is ShrincsWalletTest {
    bytes32 internal constant ACTION = keccak256("test.action");
    bytes32 internal constant PAYLOAD = keccak256("test.payload");

    function _pk() internal view returns (SHRINCS.PublicKey memory) {
        return _mainPk();
    }

    /// @dev Identical verify + bitmap consume + counter + event, but the action nonce must
    ///      stay untouched.
    function test_exposed_verifyStatefulAndConsume_doesNotAdvanceNonce() public {
        bytes32 payloadHash = keccak256("consume-payload");
        SHRINCS.Signature memory sig =
            _signStatefulAction(Codec.ACTION_MARK_LEAVES_USED, payloadHash, 1);

        vm.expectEmit(true, true, false, false, address(wallet));
        emit IShrincsWallet.StatefulSignatureVerified(SIGN_BASE + 1, 0);
        uint32 leaf = wallet.exposed_verifyStatefulAndConsume(
            _pk(), sig, Codec.ACTION_MARK_LEAVES_USED, payloadHash
        );

        assertEq(leaf, SIGN_BASE + 1, "consumed leaf returned");
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf 1 marked used");
        assertEq(wallet.statefulLeavesUsed(), 1, "used counter incremented");
        assertEq(wallet.actionNonce(), 0, "consume variant must NOT advance the action nonce");
    }

    /// @dev The surgical property at helper level: a signature outstanding when a consume-only
    ///      verification lands still binds the live nonce, so it remains valid — unlike after
    ///      an advance, which supersedes it.
    function test_exposed_verifyStatefulAndConsume_preservesOutstandingSignatures() public {
        bytes32 p1 = keccak256("consumed-first");
        bytes32 p2 = keccak256("outstanding");
        // Both signed against the SAME live nonce (0), before either lands.
        SHRINCS.Signature memory s1 = _signStatefulAction(Codec.ACTION_MARK_LEAVES_USED, p1, 1);
        SHRINCS.Signature memory s2 = _signStatefulAction(Codec.ACTION_EXECUTE, p2, 2);

        wallet.exposed_verifyStatefulAndConsume(_pk(), s1, Codec.ACTION_MARK_LEAVES_USED, p1);
        // The outstanding signature still verifies: the consume did not supersede it.
        wallet.exposed_verifyStatefulAndAdvance(_pk(), s2, Codec.ACTION_EXECUTE, p2);
        assertEq(wallet.actionNonce(), 1, "only the advancing consume moved the nonce");
        assertEq(wallet.statefulLeavesUsed(), 2, "both leaves consumed");
    }

    function test_exposed_verifyStatefulAndConsume_revertsWhen_leafZero() public {
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.exposed_verifyStatefulAndConsume(_pk(), _statefulSigWithLeaf(0), ACTION, PAYLOAD);
    }

    function test_exposed_verifyStatefulAndConsume_revertsWhen_leafOverBudget() public {
        vm.expectRevert(IShrincsWallet.StatefulBudgetExhausted.selector);
        wallet.exposed_verifyStatefulAndConsume(
            _pk(), _statefulSigWithLeaf(uint256(MAX_SIG) + 1), ACTION, PAYLOAD
        );
    }

    function test_exposed_verifyStatefulAndConsume_revertsWhen_leafAlreadyUsed() public {
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        vm.expectRevert(IShrincsWallet.StaleStatefulLeaf.selector);
        wallet.exposed_verifyStatefulAndConsume(
            _pk(), _statefulSigWithLeaf(SIGN_BASE + 1), ACTION, PAYLOAD
        );
    }

    function test_exposed_verifyStatefulAndConsume_revertsWhen_invalidSignature() public {
        SHRINCS.Signature memory sig = _wrongContextStatefulSig();
        vm.expectRevert(IShrincsWallet.InvalidSignature.selector);
        wallet.exposed_verifyStatefulAndConsume(_pk(), sig, ACTION, PAYLOAD);
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1), "leaf not consumed on invalid signature");
    }
}
