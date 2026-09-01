// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {SPHINCSPlusC} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SPHINCSPlusC.sol";
import {UXMSS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/UXMSS.sol";
import {HashSuite} from "shrincs-hash/HashSuite.sol";
import {SHRINCSParams} from "shrincs-profile/SHRINCSParams.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";

/// @dev Behavior tests for the wallet's view getters.
contract ShrincsWallet_views is ShrincsWalletTest {
    function test_owner() public view {
        assertEq(wallet.owner(), OWNER);
    }

    function test_quipFactory() public view {
        assertEq(wallet.walletFactory(), address(factory));
    }

    function test_getExecuteFee_reflectsFactory() public {
        _setExecuteFee(123);
        assertEq(wallet.getExecuteFee(), 123);
    }

    function test_getCommitments() public view {
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment);
        assertEq(wallet.getErc1271PublicKeyCommitment(), erc1271Commitment);
    }

    function test_getHashSuites() public view {
        assertEq(wallet.getHashSuite(), HashSuite.HASH_SUITE_ID);
        assertEq(wallet.getErc1271HashSuite(), HashSuite.HASH_SUITE_ID);
    }

    function test_getShrincsVerifier() public view {
        assertEq(wallet.getShrincsVerifier(), address(shrincsVerifier), "view getter");
        assertEq(wallet.SHRINCS_VERIFIER(), address(shrincsVerifier), "public immutable getter");
    }

    function test_epochCountersStartZero() public view {
        assertEq(wallet.keyVersion(), 0);
        assertEq(wallet.actionNonce(), 0);
        assertEq(wallet.statefulLeavesUsed(), 0);
    }

    function test_maxAndRemainingSignatures() public {
        assertEq(wallet.maxSignatures(), MAX_SIG);
        assertEq(wallet.remainingStatefulSignatures(), MAX_SIG);
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        assertEq(wallet.statefulLeavesUsed(), 1);
        assertEq(wallet.remainingStatefulSignatures(), MAX_SIG - 1);
    }

    /// @dev The advisory counter must never underflow/revert if it ever drifts above
    ///      `maxSignatures`; the leaf bitmap is the real anti-replay mechanism.
    function test_remainingStatefulSignatures_saturatesOnDrift() public {
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        wallet.harness_markLeafUsed(SIGN_BASE + 2);
        assertEq(wallet.statefulLeavesUsed(), 2);
        // Force the counter above max: drop max below the used count.
        wallet.harness_setMaxSignatures(1);
        assertEq(wallet.remainingStatefulSignatures(), 0);
        // Equal counts also saturate to zero.
        wallet.harness_setMaxSignatures(2);
        assertEq(wallet.remainingStatefulSignatures(), 0);
    }

    function test_isStatefulLeafUsed_reflectsBitmap() public {
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 1));
        wallet.harness_markLeafUsed(SIGN_BASE + 1);
        assertTrue(wallet.isStatefulLeafUsed(SIGN_BASE + 1));
        assertFalse(wallet.isStatefulLeafUsed(SIGN_BASE + 2));
    }

    function test_statefulLeafBitmapWord_packsConsumedLeaves() public {
        assertEq(wallet.statefulLeafBitmapWord(0), 0, "word 0 starts empty");
        wallet.harness_markLeafUsed(1);
        wallet.harness_markLeafUsed(5);
        assertEq(
            wallet.statefulLeafBitmapWord(0),
            (uint256(1) << 1) | (uint256(1) << 5),
            "word 0 packs consumed leaves 1 and 5"
        );
        assertEq(wallet.statefulLeafBitmapWord(1), 0, "untouched word reads zero");
    }

    function test_ownershipHandoverExpiresAt_alwaysZero() public view {
        assertEq(wallet.ownershipHandoverExpiresAt(OWNER), 0);
        assertEq(wallet.ownershipHandoverExpiresAt(address(0xCAFE)), 0);
    }

    function test_version_vettedIndex() public view {
        // The factory-deployed wallet points at the vetted harness implementation (index 0).
        assertEq(wallet.version(), 0, "vetted index surfaced");
    }

    function test_version_unvettedSentinel() public {
        // A bare implementation instance (not behind a proxy) has an empty ERC-1967 slot, so
        // its installed-impl codehash reads 0 — never vetted, and the sentinel surfaces.
        ShrincsWalletHarness bare =
            new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
        assertEq(bare.version(), type(uint256).max, "unvetted sentinel");
    }
}
