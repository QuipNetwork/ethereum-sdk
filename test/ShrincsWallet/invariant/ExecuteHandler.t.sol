// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";

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

    function initialize(ShrincsWalletHarness wallet_, address owner_) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
        owner = owner_;
    }

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
