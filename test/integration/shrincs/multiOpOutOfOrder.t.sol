// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsE2EBase} from "./ShrincsE2EBase.t.sol";

/// @dev e2e proof that the one-time-leaf bitmaps are independent of the EntryPoint's sequential nonce:
///      leaves are consumed in ANY order, and a consumed leaf cannot be replayed even under a fresh,
///      valid EntryPoint nonce.
contract ShrincsE2E_multiOpOutOfOrder is ShrincsE2EBase {
    /// @dev Two sponsored ops with sequential nonces (0,1) but DECREASING leaves (3,2). Both land,
    ///      proving leaf order need not match nonce order.
    function test_e2e_outOfOrderLeavesAccepted() public {
        _handle(_checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 0, 3)); // nonce 0, leaves 3/3
        _handle(_checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 1, 2)); // nonce 1, leaves 2/2

        assertTrue(wallet.isStatefulLeafUsed(3), "wallet leaf 3 consumed");
        assertTrue(wallet.isStatefulLeafUsed(2), "wallet leaf 2 consumed");
        assertTrue(paymaster.isStatefulLeafUsed(3), "pm leaf 3 consumed");
        assertTrue(paymaster.isStatefulLeafUsed(2), "pm leaf 2 consumed");
        // A leaf BELOW the consumed ones stays free — no sequential watermark.
        assertFalse(wallet.isStatefulLeafUsed(1), "wallet leaf 1 still free");
    }

    /// @dev After leaf 3 is consumed (nonce 0), a later op (correct next nonce 2) that re-signs the
    ///      SAME wallet leaf 3 is rejected by the wallet's used-leaf bitmap — the EntryPoint nonce is
    ///      valid, so this isolates the wallet-side replay guard as `AA24 signature error`.
    function test_e2e_staleWalletLeafRejected() public {
        _handle(_checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 0, 3)); // nonce 0 consumes wallet leaf 3
        _handle(_checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 1, 2)); // nonce 1 (advance the EntryPoint nonce to 2)

        // nonce 2, reuses wallet leaf 3 with a fresh paymaster leaf 4
        PackedUserOperation memory stale =
            _buildSponsoredOp(RECIPIENT, 0.1 ether, "", 2, 3, 4, 0, 0, false, 0, 0, false);
        _assertLiveHash(stale);
        _handleExpectRevert(stale, _failedOp(0, "AA24 signature error"));
        // The fresh paymaster leaf was NOT consumed (validation reverted before paymaster effect).
        assertFalse(paymaster.isStatefulLeafUsed(4), "pm leaf 4 not consumed");
    }
}
