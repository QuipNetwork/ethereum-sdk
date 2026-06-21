// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsPaymasterTest} from "../ShrincsPaymaster.t.sol";

/// @dev Pins that the paymaster's owner-initialization guard is enabled. Unlike the wallet (which
///      inherits this from Solady's `ERC4337` base), the paymaster inherits `Ownable` directly and
///      MUST override `_guardInitializeOwner => true` itself so `_initializeOwner` reverts
///      `AlreadyInitialized` on a second call (defence in depth alongside the `initializer` modifier).
contract ShrincsPaymaster__guardInitializeOwner is ShrincsPaymasterTest {
    function test_guardInitializeOwner_returnsTrue() public view {
        assertTrue(paymaster.exposed_guardInitializeOwner());
    }
}
