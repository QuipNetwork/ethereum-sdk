// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.2.0/contracts/ShrincsTypes.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the wallet's view getters.
contract ShrincsWallet_views is ShrincsWalletTest {
    function test_owner() public view {
        assertEq(wallet.owner(), OWNER);
    }

    function test_quipFactory() public view {
        assertEq(wallet.quipFactory(), address(factory));
    }

    function test_getExecuteFee_reflectsFactory() public {
        factory.setExecuteFee(123);
        assertEq(wallet.getExecuteFee(), 123);
    }

    function test_getCommitments() public view {
        assertEq(wallet.getShrincsPublicKeyCommitment(), mainCommitment);
        assertEq(wallet.getErc1271Commitment(), erc1271Commitment);
    }

    function test_getHashSuites() public view {
        assertEq(wallet.getHashSuite(), ShrincsTypes.HASH_SUITE_KECCAK_256);
        assertEq(wallet.getErc1271HashSuite(), ShrincsTypes.HASH_SUITE_KECCAK_256);
    }

    function test_epochCountersStartZero() public view {
        assertEq(wallet.keyVersion(), 0);
        assertEq(wallet.actionNonce(), 0);
        assertEq(wallet.statefulLeavesUsed(), 0);
    }

    function test_maxAndRemainingSignatures() public {
        assertEq(wallet.maxSignatures(), MAX_SIG);
        assertEq(wallet.remainingStatefulSignatures(), MAX_SIG);
        wallet.harness_markLeafUsed(1);
        assertEq(wallet.statefulLeavesUsed(), 1);
        assertEq(wallet.remainingStatefulSignatures(), MAX_SIG - 1);
    }

    function test_isStatefulLeafUsed_reflectsBitmap() public {
        assertFalse(wallet.isStatefulLeafUsed(1));
        wallet.harness_markLeafUsed(1);
        assertTrue(wallet.isStatefulLeafUsed(1));
        assertFalse(wallet.isStatefulLeafUsed(2));
    }

    function test_ownershipHandoverExpiresAt_alwaysZero() public view {
        assertEq(wallet.ownershipHandoverExpiresAt(OWNER), 0);
        assertEq(wallet.ownershipHandoverExpiresAt(address(0xCAFE)), 0);
    }

    function test_version_unvettedThenVetted() public {
        // The etched harness has a zero ERC-1967 implementation slot ⇒ impl codehash is 0.
        assertEq(wallet.version(), type(uint256).max, "unvetted sentinel");
        factory.vet(bytes32(0), 5);
        assertEq(wallet.version(), 5, "vetted index surfaced");
    }
}
