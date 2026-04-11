// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

contract QuipPaymaster_getPqVerifier is QuipPaymasterTest {
    function test_getPqVerifier_returnsCorrectVerifierForRegisteredWallet() public view {
        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(WALLET);
        assertEq(v.publicSeed, verifierPubkey.publicSeed);
        assertEq(v.publicKeyHash, verifierPubkey.publicKeyHash);
    }

    function test_getPqVerifier_returnsZeroForUnregisteredWallet() public {
        address unknown = makeAddr("unknown-wallet");
        WOTSPlus.WinternitzAddress memory v = paymaster.getPqVerifier(unknown);
        assertEq(v.publicSeed, bytes32(0));
        assertEq(v.publicKeyHash, bytes32(0));
    }
}
