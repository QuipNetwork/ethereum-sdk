// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletInvariantBase} from "./InvariantBase.sol";
import {ShrincsWalletInvariantHandler} from "./Handler.t.sol";

/// @title ShrincsWallet — Local Invariant Suite (revocation lifecycle)
/// @dev Stateful fuzz over two surfaces: the disabled classical/uncapped
///      entry points (exact revert reasons asserted) and `markLeavesUsed`
///      both with garbage signatures (must never succeed) and the
///      pre-signed replay pool (first replay per entry succeeds, later
///      replays exercise stale-leaf and skip paths).
///
///      Scope: every valid path in this suite is revocation-only, which is
///      nonce-neutral by the INVARIANTS.md §17 carve-out and epoch-neutral
///      (no rotation selector exists here). `nonceStable`/`epochStable` are
///      therefore load-bearing properties OF THIS SUITE — adding a
///      rotation/execute selector must revisit them. Pins §17 (failed
///      verification advances nothing; revocation never advances the nonce),
///      §25 (spent-tree registry untouched without installs) and the
///      disabled-ownership surface.
contract ShrincsWallet_Local_Invariant is ShrincsWalletInvariantBase {
    function setUp() public override {
        super.setUp();
        targetContract(address(handler));

        bytes4[] memory selectors = new bytes4[](8);
        selectors[0] = ShrincsWalletInvariantHandler
            .fuzzDisabledRenounce
            .selector;
        selectors[1] = ShrincsWalletInvariantHandler
            .fuzzClassicalTransfer
            .selector;
        selectors[2] = ShrincsWalletInvariantHandler.fuzzHandover.selector;
        selectors[3] = ShrincsWalletInvariantHandler
            .fuzzClassicalWithdraw
            .selector;
        selectors[4] = ShrincsWalletInvariantHandler
            .fuzzDisabledExecute
            .selector;
        selectors[5] = ShrincsWalletInvariantHandler
            .fuzzDisabledDelegate
            .selector;
        selectors[6] = ShrincsWalletInvariantHandler
            .fuzzInvalidMarkLeavesUsed
            .selector;
        selectors[7] = ShrincsWalletInvariantHandler
            .fuzzValidMarkReplay
            .selector;
        targetSelector(
            FuzzSelector({addr: address(handler), selectors: selectors})
        );
    }

    function invariant_noDisabledSuccess() public view {
        assertEq(handler.callsDisabled(), 0, "disabled entry point succeeded");
    }

    function invariant_noInvalidMarkSuccess() public view {
        assertEq(
            handler.callsInvalidMark(),
            0,
            "garbage-signature revocation succeeded"
        );
    }

    function invariant_noBadReason() public view {
        assertEq(
            handler.badReasonCount(),
            0,
            "disabled path reverted with wrong reason"
        );
    }

    function invariant_ownerStable() public view {
        assertEq(wallet.owner(), OWNER, "wallet owner drifted");
    }

    function invariant_nonceStable() public view {
        assertEq(
            wallet.actionNonce(),
            initialNonce,
            "nonce advanced without a consuming action"
        );
    }

    function invariant_epochStable() public view {
        assertEq(
            wallet.keyVersion(),
            initialKeyVersion,
            "keyVersion changed without rotation"
        );
    }

    function invariant_maxStable() public view {
        assertEq(wallet.maxSignatures(), MAX_SIG, "maxSignatures drifted");
    }

    function invariant_usedMonotone() public view {
        assertGe(
            wallet.statefulLeavesUsed(),
            initialUsed,
            "used counter decreased"
        );
    }

    function invariant_usedBounded() public view {
        assertLe(
            wallet.statefulLeavesUsed(),
            wallet.maxSignatures(),
            "used exceeds max"
        );
    }

    function invariant_remainingConsistent() public view {
        uint32 maxSig = wallet.maxSignatures();
        uint32 used = wallet.statefulLeavesUsed();
        uint32 expected = used >= maxSig ? 0 : maxSig - used;
        assertEq(
            wallet.remainingStatefulSignatures(),
            expected,
            "remaining inconsistent"
        );
    }

    function invariant_bitmapMonotonic() public view {
        uint256 n = handler.everSeenCount();
        uint256 checked;
        for (
            uint256 leaf = 1;
            leaf <= wallet.maxSignatures() && checked < n;
            leaf++
        ) {
            if (!handler.isSeen(leaf)) continue;
            checked++;
            assertTrue(wallet.isStatefulLeafUsed(leaf), "used leaf cleared");
        }
        assertEq(checked, n, "mirror references leaves outside range");
    }

    function invariant_usedMatchesMirror() public view {
        assertEq(
            wallet.statefulLeavesUsed(),
            handler.everSeenCount(),
            "used counter diverged from mirror"
        );
    }

    function invariant_commitmentsStable() public view {
        assertEq(
            wallet.getShrincsPublicKeyCommitment(),
            initialMainCommitment,
            "main commitment drifted"
        );
        assertEq(
            wallet.getErc1271PublicKeyCommitment(),
            initialErc1271Commitment,
            "1271 commitment drifted"
        );
    }

    function invariant_factoryStable() public view {
        assertEq(
            address(wallet.walletFactory()),
            address(factory),
            "factory pointer drifted"
        );
    }

    function invariant_verifierStable() public view {
        assertEq(
            wallet.getShrincsVerifier(),
            address(shrincsVerifier),
            "verifier drifted"
        );
    }

    function invariant_spentTreesStable() public view {
        _assertTreesSpent(mainPk);
        _assertTreesSpent(erc1271Pk);
    }
}
