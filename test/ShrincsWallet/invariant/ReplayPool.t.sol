// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletInvariantBase} from "./support/InvariantBase.sol";

contract ShrincsWallet_ReplayPoolLiveness is ShrincsWalletInvariantBase {
    function test_replayPoolLandsSuccess() public {
        uint32 usedBefore = wallet.statefulLeavesUsed();
        handler.fuzzValidMarkReplay(0);
        handler.fuzzValidMarkReplay(1);
        handler.fuzzValidMarkReplay(2);
        assertEq(handler.callsValidMark(), 3, "every pool entry must succeed on first replay");
        assertEq(
            wallet.statefulLeavesUsed(),
            usedBefore + 5,
            "pool must consume auth leaves 35/36/37 plus targets 38/39"
        );
        assertEq(handler.callsInvalidMark(), 0, "valid replay counted invalid");

        handler.fuzzValidMarkReplay(0);
        assertEq(handler.callsValidMark(), 3, "stale replay must not succeed");
        assertEq(wallet.statefulLeavesUsed(), usedBefore + 5, "stale replay consumed a leaf");
    }
}
