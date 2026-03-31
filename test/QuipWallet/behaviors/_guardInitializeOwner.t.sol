// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";
import {QuipWalletHarness} from "../../harness/QuipWalletHarness.sol";

contract QuipWallet___guardInitializeOwner is QuipWalletTest {
    QuipWalletHarness public harness;

    function setUp() public override {
        super.setUp();
        harness = new QuipWalletHarness(payable(address(factory)));
    }

    function test_exposed_guardInitializeOwner_returnsTrue() public view {
        assertTrue(harness.exposed_guardInitializeOwner());
    }
}
