// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {Vm} from "forge-std-1.14.0/Vm.sol";
import {ERC4337} from "solady-0.1.26/src/accounts/ERC4337.sol";
import {IShrincsWallet} from "../../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../../harness/ShrincsWalletHarness.sol";

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

    function initialize(ShrincsWalletHarness wallet_) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
    }

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

    function fuzzValidateReplay(uint256 idx) external {
        if (pool.length == 0) return;
        idx = bound(idx, 0, pool.length - 1);
        ValidationEntry storage entry = pool[idx];
        vm.recordLogs();
        uint256 result = wallet.exposed_validateSignature(
            entry.op,
            entry.userOpHash
        );
        if (idx == successIdx.length) {
            assertEq(result, 0, "next signed validation must succeed");
        } else {
            assertEq(result, 1, "out-of-order validation must fail");
        }
        if (result == 0) {
            callsValidate++;
            successIdx.push(idx);
            return;
        }
        uint256 reason = _rejectionReason();
        if (
            reason ==
            uint256(IShrincsWallet.UserOpValidationFailure.InvalidSignature)
        ) {
            assertGt(
                idx,
                successIdx.length,
                "only future validation has an invalid signature"
            );
            staleCount++;
        } else if (
            reason ==
            uint256(IShrincsWallet.UserOpValidationFailure.StaleStatefulLeaf)
        ) {
            assertLt(
                idx,
                successIdx.length,
                "only landed validation uses a stale leaf"
            );
            staleUsedCount++;
        } else {
            badReasonCount++;
        }
    }

    function _rejectionReason() internal returns (uint256) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (
                logs[i].topics[0] ==
                IShrincsWallet.UserOpValidationRejected.selector
            ) {
                return uint256(logs[i].topics[1]);
            }
        }
        return type(uint256).max;
    }
}
