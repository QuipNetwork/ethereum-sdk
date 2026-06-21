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
        PackedUserOperation memory op = _op("sponsoredEthTransfer");
        // Flip a byte deep inside the wallet signature blob (past the ABI header).
        op.signature[op.signature.length - 1] ^= bytes1(0x01);
        _handleExpectRevert(op, _failedOp(0, "AA24 signature error"));
    }

    /// @dev The paymaster signed a corrupted binding hash, so `verifyStateful` fails and the paymaster
    ///      returns `("",1)`; the wallet sig is valid, so the failure is isolated to the paymaster →
    ///      `AA34`.
    function test_e2e_badPaymasterSig_AA34() public {
        _handleExpectRevert(
            _op("badPaymasterContext"),
            _failedOp(0, "AA34 signature error")
        );
    }

    /// @dev `validAfter` far in the future → the paymaster validates but the EntryPoint rejects the
    ///      time range as not-yet-due (`AA32`). The bound is an absolute timestamp baked into the
    ///      signed prefix, so the result is fork-time-independent.
    function test_e2e_windowNotDue_AA32() public {
        _handleExpectRevert(
            _op("windowNotDue"),
            _failedOp(0, "AA32 paymaster expired or not due")
        );
    }

    /// @dev `validUntil` already elapsed → `AA32`.
    function test_e2e_windowExpired_AA32() public {
        _handleExpectRevert(
            _op("windowExpired"),
            _failedOp(0, "AA32 paymaster expired or not due")
        );
    }
}
