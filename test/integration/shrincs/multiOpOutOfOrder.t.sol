// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsE2EBase} from "./ShrincsE2EBase.t.sol";

/// @dev e2e proof of the two anti-replay layers: leaf INDICES carry no ordering constraint (any
///      unused leaf works), while the wallet's action nonce strictly serializes SIGNING order —
///      each landed op advances it, so op N in a sequence must bind walletNonce N. A consumed
///      leaf cannot be replayed, and a superseded (stale-nonce) signature is dead even with a
///      fresh leaf and a fresh EntryPoint nonce.
contract ShrincsE2E_multiOpOutOfOrder is ShrincsE2EBase {
    /// @dev Two sponsored ops with sequential nonces (0,1) but DECREASING leaves (3,2). Both land:
    ///      leaf order need not match nonce order (each op binds its sequential wallet nonce).
    function test_e2e_outOfOrderLeavesAccepted() public {
        _handle(_checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 0, 3, 0)); // nonce 0, leaves 3/3, walletNonce 0
        _handle(_checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 1, 2, 1)); // nonce 1, leaves 2/2, walletNonce 1

        assertTrue(wallet.isStatefulLeafUsed(3), "wallet leaf 3 consumed");
        assertTrue(wallet.isStatefulLeafUsed(2), "wallet leaf 2 consumed");
        assertTrue(paymaster.isStatefulLeafUsed(3), "pm leaf 3 consumed");
        assertTrue(paymaster.isStatefulLeafUsed(2), "pm leaf 2 consumed");
        // A leaf BELOW the consumed ones stays free — no sequential watermark.
        assertFalse(wallet.isStatefulLeafUsed(1), "wallet leaf 1 still free");
        assertEq(wallet.actionNonce(), 2, "each landed op advanced the wallet nonce");
    }

    /// @dev After leaf 3 is consumed (nonce 0), a later op (correct next nonce 2, correct wallet
    ///      nonce 2) that re-signs the SAME wallet leaf 3 is rejected by the wallet's used-leaf
    ///      bitmap — EntryPoint nonce and wallet nonce are both valid, so this isolates the
    ///      leaf-replay guard as `AA24 signature error`.
    function test_e2e_staleWalletLeafRejected() public {
        _handle(_checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 0, 3, 0)); // consumes wallet leaf 3
        _handle(_checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 1, 2, 1)); // advances EP nonce to 2

        // EP nonce 2, wallet nonce 2 (both fresh), reuses wallet leaf 3 with fresh paymaster leaf 4.
        PackedUserOperation memory stale =
            _buildSponsoredOp(RECIPIENT, 0.1 ether, "", 2, 3, 4, 0, 0, false, 0, 0, 2, false);
        _assertLiveHash(stale);
        _handleExpectRevert(stale, _failedOp(0, "AA24 signature error"));
        // The fresh paymaster leaf was NOT consumed (validation reverted before paymaster effect).
        assertFalse(paymaster.isStatefulLeafUsed(4), "pm leaf 4 not consumed");
    }

    /// @dev Supersession e2e: an op with a fresh leaf AND a fresh EntryPoint nonce but a STALE
    ///      wallet action nonce is rejected `AA24` — this isolates the nonce freshness guard.
    function test_e2e_staleWalletNonceRejected() public {
        _handle(_checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 0, 1, 0)); // advances wallet nonce to 1

        // EP nonce 1 (valid), leaf 2 (unused), but wallet nonce 0 (superseded).
        PackedUserOperation memory stale =
            _buildSponsoredOp(RECIPIENT, 0.1 ether, "", 1, 2, 2, 0, 0, false, 0, 0, 0, false);
        _assertLiveHash(stale);
        _handleExpectRevert(stale, _failedOp(0, "AA24 signature error"));
        assertFalse(wallet.isStatefulLeafUsed(2), "superseded op's wallet leaf not consumed");
        assertFalse(paymaster.isStatefulLeafUsed(2), "pm leaf not consumed");
        assertEq(wallet.actionNonce(), 1, "wallet nonce unchanged by the rejection");
    }
}
