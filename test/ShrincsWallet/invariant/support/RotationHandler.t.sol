// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {IShrincsWallet} from "../../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../../harness/ShrincsWalletHarness.sol";

contract ShrincsWalletRotationHandler is Test {
    struct RotationEntry {
        SHRINCS.PublicKey pk;
        SHRINCS.Signature sig;
        SHRINCS.StatefulRotationTarget target;
        bytes32 nextCommitment;
        bytes32 nextTreeId;
    }

    ShrincsWalletHarness internal wallet;
    address internal owner;
    RotationEntry[] internal pool;
    uint256[] internal successIdx;
    uint256 public callsRotate;
    uint256 public staleCount;
    uint256 public badReasonCount;

    function initialize(ShrincsWalletHarness wallet_, address owner_) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
        owner = owner_;
    }

    function pushValidRotation(
        SHRINCS.PublicKey calldata pk,
        SHRINCS.Signature calldata sig,
        SHRINCS.StatefulRotationTarget calldata target,
        bytes32 nextCommitment,
        bytes32 nextTreeId
    ) external {
        pool.push();
        RotationEntry storage slot = pool[pool.length - 1];
        slot.pk = pk;
        slot.sig = sig;
        slot.target = target;
        slot.nextCommitment = nextCommitment;
        slot.nextTreeId = nextTreeId;
    }

    function poolLength() external view returns (uint256) {
        return pool.length;
    }

    function entryNextCommitment(uint256 i) external view returns (bytes32) {
        return pool[i].nextCommitment;
    }

    function entryNextTreeId(uint256 i) external view returns (bytes32) {
        return pool[i].nextTreeId;
    }

    function successLength() external view returns (uint256) {
        return successIdx.length;
    }

    function successAt(uint256 i) external view returns (uint256) {
        return successIdx[i];
    }

    function fuzzRotateReplay(uint256 idx) external {
        if (pool.length == 0) return;
        idx = bound(idx, 0, pool.length - 1);
        RotationEntry storage entry = pool[idx];
        vm.prank(owner);
        (bool ok, bytes memory ret) = address(wallet).call(
            abi.encodeCall(
                IShrincsWallet.rotateKey,
                (entry.pk, entry.sig, entry.target)
            )
        );
        if (idx == successIdx.length) {
            assertTrue(ok, "next signed rotation must succeed");
        } else {
            assertFalse(ok, "out-of-order rotation must fail");
        }
        if (ok) {
            callsRotate++;
            successIdx.push(idx);
            return;
        }
        bytes4 revertSelector;
        if (ret.length >= 4) {
            assembly ("memory-safe") {
                revertSelector := mload(add(ret, 0x20))
            }
        }
        if (revertSelector == IShrincsWallet.InvalidSignature.selector) {
            staleCount++;
        } else {
            badReasonCount++;
        }
    }
}
