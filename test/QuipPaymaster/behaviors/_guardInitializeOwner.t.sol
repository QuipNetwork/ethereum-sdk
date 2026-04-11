// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipPaymasterTest} from "../QuipPaymaster.t.sol";

contract QuipPaymaster__guardInitializeOwner is QuipPaymasterTest {
    function test_exposed_guardInitializeOwner_returnsTrue() public view {
        assertTrue(harness.exposed_guardInitializeOwner());
    }
}
