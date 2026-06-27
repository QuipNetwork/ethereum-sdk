// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Pins that the wallet's owner-initialization guard is enabled. The wallet does NOT override
///      `_guardInitializeOwner` itself — it inherits the `=> true` override from Solady's `ERC4337`
///      base, which makes `_initializeOwner` revert `AlreadyInitialized` on a second call (defence
///      in depth alongside the `initializer` modifier). This test fails loudly if a future refactor
///      drops the ERC4337 inheritance and silently re-enables double-initialization.
contract ShrincsWallet__guardInitializeOwner is ShrincsWalletTest {
    function test_guardInitializeOwner_returnsTrue() public view {
        assertTrue(wallet.exposed_guardInitializeOwner());
    }
}
