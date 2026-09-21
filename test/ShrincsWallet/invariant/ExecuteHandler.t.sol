// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";

/// @title ShrincsWallet Execute Fuzz Handler
/// @dev Replays a pre-signed CHAIN of `execute` authorizations. Entry `k` is
///      bound to action nonce `k`, so it succeeds if and only if every entry
///      before it already landed: the successful set is always the prefix
///      `{0..m-1}` where `m` is the success count. Out-of-order replays (fresh
///      leaf, superseded nonce) revert with `InvalidSignature`; duplicate
///      replays of a consumed entry revert with `StaleStatefulLeaf` — the
///      wallet checks the used-leaf bitmap before verifying the signature.
///      Both are counted as stale; any other revert reason is recorded
///      separately and must never occur.
contract ShrincsWalletExecuteHandler is Test {
    struct ExecuteEntry {
        SHRINCS.PublicKey pk;
        SHRINCS.Signature sig;
        address target;
        uint256 value;
        bytes data;
        uint256 maxFee;
        uint32 leaf;
    }

    ShrincsWalletHarness internal wallet;
    address internal owner;
    ExecuteEntry[] internal pool;
    uint256[] internal successIdx;
    uint256 public callsExecute;
    uint256 public staleCount;
    uint256 public staleUsedCount;
    uint256 public badReasonCount;

    /// @dev Called once from the suite setUp. The pool is pushed entry by
    ///      entry afterwards; fuzzing starts only after the full chain is
    ///      seeded. Idempotent guard — a re-init would clobber the pool.
    function initialize(ShrincsWalletHarness wallet_, address owner_) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
        owner = owner_;
    }

    /// @dev Setup-only: appends one chained execute authorization. Not a
    ///      fuzz selector (the suite allowlists `fuzzExecuteReplay` only).
    function pushValidExecute(
        SHRINCS.PublicKey calldata pk,
        SHRINCS.Signature calldata sig,
        address target,
        uint256 value,
        bytes calldata data,
        uint256 maxFee,
        uint32 leaf
    ) external {
        pool.push();
        ExecuteEntry storage slot = pool[pool.length - 1];
        slot.pk = pk;
        slot.sig = sig;
        slot.target = target;
        slot.value = value;
        slot.data = data;
        slot.maxFee = maxFee;
        slot.leaf = leaf;
    }

    function poolLength() external view returns (uint256) {
        return pool.length;
    }

    function entryLeaf(uint256 i) external view returns (uint32) {
        return pool[i].leaf;
    }

    function entryValue(uint256 i) external view returns (uint256) {
        return pool[i].value;
    }

    function entryTarget(uint256 i) external view returns (address) {
        return pool[i].target;
    }

    function successLength() external view returns (uint256) {
        return successIdx.length;
    }

    function successAt(uint256 i) external view returns (uint256) {
        return successIdx[i];
    }

    /// @dev Replays pool entry `idx` as the owner. A landing entry advances
    ///      the wallet nonce by exactly one; every other replay is stale by
    ///      construction (`InvalidSignature` for a superseded nonce,
    ///      `StaleStatefulLeaf` for a consumed leaf).
    function fuzzExecuteReplay(uint256 idx) external {
        if (pool.length == 0) return;
        idx = bound(idx, 0, pool.length - 1);
        ExecuteEntry storage entry = pool[idx];
        vm.prank(owner);
        (bool ok, bytes memory ret) = address(wallet).call(
            abi.encodeCall(
                IShrincsWallet.execute,
                (entry.pk, entry.sig, entry.target, entry.value, entry.data, entry.maxFee)
            )
        );
        if (ok) {
            callsExecute++;
            successIdx.push(idx);
            return;
        }
        if (ret.length >= 4 && bytes4(ret) == IShrincsWallet.InvalidSignature.selector) {
            staleCount++;
        } else if (ret.length >= 4 && bytes4(ret) == IShrincsWallet.StaleStatefulLeaf.selector) {
            staleUsedCount++;
        } else {
            badReasonCount++;
        }
    }
}
