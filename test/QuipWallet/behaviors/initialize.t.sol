// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipWallet_initialize is QuipWalletTest {
    function test_initialize_revertsWhen_alreadyInitialized() public {
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-seed");

        vm.prank(ALICE);
        vm.expectRevert("Already initialized");
        wallet.initialize(newPubkey);
    }

    function test_initialize_revertsWhen_callerNotOwnerOrFactory() public {
        // Deploy a fresh wallet that hasn't been initialized through the factory
        // We can't easily test this since factory always initializes,
        // but we can verify the revert on re-initialize
        (WOTSPlus.WinternitzAddress memory newPubkey,) = _generateKeyPair("new-seed");

        vm.prank(BOB);
        vm.expectRevert("You aren't the owner or creator");
        wallet.initialize(newPubkey);
    }
}
