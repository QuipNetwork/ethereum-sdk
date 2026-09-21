// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";

/// @title ShrincsWallet Validation Fuzz Handler
/// @dev Replays a pre-signed CHAIN of ERC-4337 userOps through the harness's
///      exposed `_validateSignature`. Entry `k` is bound to wrapper nonce
///      `k`, so it validates if and only if every entry before it already
///      did: successes always form the prefix `{0..m-1}`.
///
///      Validation never reverts (the envelope self-call contains everything);
///      it returns 0 on success and 1 with a `UserOpValidationRejected`
///      reason on failure. Out-of-order replays fail as `InvalidSignature`
///      (superseded nonce); duplicates of a consumed leaf fail as
///      `StaleStatefulLeaf` (bitmap checked before verification). Both are
///      counted as stale; any other reason is recorded separately and must
///      never occur.
contract ShrincsWalletValidationHandler is Test {
    struct ValidationEntry {
        ERC4337.PackedUserOperation op;
        bytes32 userOpHash;
        uint32 leaf;
    }

    ShrincsWalletHarness internal wallet;
    ValidationEntry[] internal pool;
    uint256[] internal successIdx;
    uint256 public callsValidate;
    uint256 public staleCount;
    uint256 public staleUsedCount;
    uint256 public badReasonCount;

    /// @dev Called once from the suite setUp. The pool is pushed entry by
    ///      entry afterwards; fuzzing starts only after the full chain is
    ///      seeded. Idempotent guard — a re-init would clobber the pool.
    function initialize(ShrincsWalletHarness wallet_) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
    }

    /// @dev Setup-only: appends one chained userOp. Not a fuzz selector (the
    ///      suite allowlists `fuzzValidateReplay` only).
    function pushValidOp(
        ERC4337.PackedUserOperation calldata op,
        bytes32 userOpHash,
        uint32 leaf
    ) external {
        pool.push();
        ValidationEntry storage slot = pool[pool.length - 1];
        slot.op = op;
        slot.userOpHash = userOpHash;
        slot.leaf = leaf;
    }

    function poolLength() external view returns (uint256) {
        return pool.length;
    }

    function entryLeaf(uint256 i) external view returns (uint32) {
        return pool[i].leaf;
    }

    function successLength() external view returns (uint256) {
        return successIdx.length;
    }

    function successAt(uint256 i) external view returns (uint256) {
        return successIdx[i];
    }

    /// @dev Submits pool entry `idx` for validation — the bundler's view of
    ///      the mempool op. A landing entry advances the wrapper nonce by
    ///      exactly one and consumes its leaf; every other submission must
    ///      soft-fail with a stale reason.
    function fuzzValidateReplay(uint256 idx) external {
        if (pool.length == 0) return;
        idx = bound(idx, 0, pool.length - 1);
        ValidationEntry storage entry = pool[idx];
        vm.recordLogs();
        uint256 result = wallet.exposed_validateSignature(entry.op, entry.userOpHash);
        if (result == 0) {
            callsValidate++;
            successIdx.push(idx);
            return;
        }
        uint256 reason = _rejectionReason();
        if (reason == uint256(IShrincsWallet.UserOpValidationFailure.InvalidSignature)) {
            staleCount++;
        } else if (reason == uint256(IShrincsWallet.UserOpValidationFailure.StaleStatefulLeaf)) {
            staleUsedCount++;
        } else {
            badReasonCount++;
        }
    }

    /// @dev Reads the `UserOpValidationRejected` reason from the logs the
    ///      submission just emitted. Every rejection emits exactly one.
    function _rejectionReason() internal returns (uint256) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == IShrincsWallet.UserOpValidationRejected.selector) {
                return uint256(logs[i].topics[1]);
            }
        }
        return type(uint256).max;
    }
}
