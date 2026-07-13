// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {ShrincsE2EBase} from "./ShrincsE2EBase.t.sol";

/// @dev e2e revert paths: the EntryPoint surfaces each co-validation failure as the canonical `AAxx`
///      `FailedOp`. The account is validated before the paymaster, so an invalid wallet sig is `AA24`
///      while a paymaster-side failure (bad sig / time window) is `AA34` / `AA32`.
contract ShrincsE2E_rejections is ShrincsE2EBase {
    /// @dev Corrupting `userOp.signature` (which is excluded from `userOpHash`, so the paymaster path
    ///      stays consistent) makes the wallet's PQ verification fail → `AA24`.
    function test_e2e_invalidWalletSig_AA24() public {
        PackedUserOperation memory op = _checkedSponsoredOp(RECIPIENT, 0.1 ether, "", 0, 1);
        // Flip a byte deep inside the wallet signature blob (past the ABI header).
        op.signature[op.signature.length - 1] ^= bytes1(0x01);
        _handleExpectRevert(op, _failedOp(0, "AA24 signature error"));
    }

    /// @dev The paymaster signed a corrupted binding hash, so `verifyStateful` fails and the paymaster
    ///      returns `("",1)`; the wallet sig is valid, so the failure is isolated to the paymaster →
    ///      `AA34`.
    function test_e2e_badPaymasterSig_AA34() public {
        // The paymaster signed a flipped binding hash; the wallet signature stays valid.
        SponsoredOpParams memory p = _defaultOpParams(RECIPIENT, 0.1 ether, "", 0, 1);
        p.corruptPmBinding = true;
        PackedUserOperation memory op = _buildSponsoredOp(p);
        _assertLiveHash(op);
        _handleExpectRevert(op, _failedOp(0, "AA34 signature error"));
    }

    /// @dev `validAfter` far in the future → the paymaster validates but the EntryPoint rejects the
    ///      time range as not-yet-due (`AA32`). The bound is an absolute timestamp baked into the
    ///      signed prefix, so the result is fork-time-independent.
    function test_e2e_windowNotDue_AA32() public {
        // validAfter far in the future (year ~2096), validUntil unbounded.
        SponsoredOpParams memory p = _defaultOpParams(RECIPIENT, 0.1 ether, "", 0, 1);
        p.validUntil = type(uint48).max;
        p.validAfter = uint48(4_000_000_000);
        _handleExpectRevert(_buildSponsoredOp(p), _failedOp(0, "AA32 paymaster expired or not due"));
    }

    /// @dev `validUntil` already elapsed → `AA32`.
    function test_e2e_windowExpired_AA32() public {
        // validUntil already elapsed.
        SponsoredOpParams memory p = _defaultOpParams(RECIPIENT, 0.1 ether, "", 0, 1);
        p.validUntil = uint48(1);
        _handleExpectRevert(_buildSponsoredOp(p), _failedOp(0, "AA32 paymaster expired or not due"));
    }
}
