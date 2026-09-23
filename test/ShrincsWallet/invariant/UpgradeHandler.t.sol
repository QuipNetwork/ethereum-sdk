// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {SHRINCS} from "@quip.network/hashsigs-solidity-0.2.0/contracts/SHRINCS.sol";
import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";

contract ShrincsWalletUpgradeHandler is Test {
    struct UpgradeEntry {
        address impl;
        SHRINCS.PublicKey pk;
        SHRINCS.Signature sig;
        bool shouldMigrate;
        bytes migrator;
        uint256 blobNonce;
        bytes probe;
    }

    ShrincsWalletHarness internal wallet;
    address internal owner;
    UpgradeEntry[] internal pool;
    uint256[] internal successIdx;
    uint256 public callsUpgrade;
    uint256 public staleCount;
    uint256 public badReasonCount;

    function initialize(ShrincsWalletHarness wallet_, address owner_) external {
        require(address(wallet) == address(0), "handler already initialized");
        wallet = wallet_;
        owner = owner_;
    }

    function pushValidUpgrade(
        address impl,
        SHRINCS.PublicKey calldata pk,
        SHRINCS.Signature calldata sig,
        bool shouldMigrate,
        bytes calldata migrator,
        uint256 blobNonce,
        bytes calldata probe
    ) external {
        pool.push();
        UpgradeEntry storage slot = pool[pool.length - 1];
        slot.impl = impl;
        slot.pk = pk;
        slot.sig = sig;
        slot.shouldMigrate = shouldMigrate;
        slot.migrator = migrator;
        slot.blobNonce = blobNonce;
        slot.probe = probe;
    }

    function poolLength() external view returns (uint256) {
        return pool.length;
    }

    function entryImpl(uint256 i) external view returns (address) {
        return pool[i].impl;
    }

    function successLength() external view returns (uint256) {
        return successIdx.length;
    }

    function successAt(uint256 i) external view returns (uint256) {
        return successIdx[i];
    }

    function fuzzUpgradeReplay(uint256 idx) external {
        if (pool.length == 0) return;
        idx = bound(idx, 0, pool.length - 1);
        UpgradeEntry storage entry = pool[idx];
        bytes memory data = abi.encode(
            entry.pk,
            entry.sig,
            entry.shouldMigrate,
            entry.migrator,
            entry.blobNonce,
            entry.probe
        );
        vm.prank(owner);
        (bool ok, bytes memory ret) = address(wallet).call(
            abi.encodeCall(IShrincsWallet.upgradeToAndCall, (entry.impl, data))
        );
        if (ok) {
            callsUpgrade++;
            successIdx.push(idx);
            return;
        }
        bytes memory expectedStale = abi.encodeWithSelector(
            IShrincsWallet.StaleActionNonce.selector,
            wallet.actionNonce(),
            entry.blobNonce
        );
        if (keccak256(ret) == keccak256(expectedStale)) {
            staleCount++;
        } else {
            badReasonCount++;
        }
    }
}
