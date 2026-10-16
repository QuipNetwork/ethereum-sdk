// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";

contract WOTSPlusImplementation__guardInitializeOwner is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harness;

    function setUp() public override {
        super.setUp();
        harness = new WOTSPlusImplementationHarness(payable(address(factory)));
    }

    function test_exposed_guardInitializeOwner_returnsTrue() public view {
        assertTrue(harness.exposed_guardInitializeOwner());
    }
}
