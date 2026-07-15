// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {QuipPaymaster} from "../../../../contracts/deprecated/QuipPaymaster.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";

contract QuipPaymaster_upgradeToAndCall is QuipPaymasterTest {
    function test_upgradeToAndCall_ownerCanUpgrade() public {
        QuipPaymaster newImpl = new QuipPaymaster();

        vm.prank(ADMIN);
        paymaster.upgradeToAndCall(address(newImpl), "");

        // Verify the proxy still works after upgrade
        assertEq(paymaster.owner(), ADMIN);
        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, verifierPubkey.publicSeed);
        assertEq(v.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    function test_upgradeToAndCall_revertsWhen_notOwner() public {
        QuipPaymaster newImpl = new QuipPaymaster();

        vm.prank(ALICE);
        vm.expectRevert(Ownable.Unauthorized.selector);
        paymaster.upgradeToAndCall(address(newImpl), "");
    }
}
