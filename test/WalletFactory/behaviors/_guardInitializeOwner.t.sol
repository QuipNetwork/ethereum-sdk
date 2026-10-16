// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {LibClone} from "solady-0.1.26/src/utils/LibClone.sol";
import {WalletFactoryTest} from "../WalletFactory.t.sol";
import {WalletFactoryHarness} from "../../harness/WalletFactoryHarness.sol";

/// @dev Pins that the factory's owner-initialization guard is enabled. The factory inherits Solady
///      `Ownable` directly (not the `ERC4337` base that supplies this override for the wallet), so it
///      MUST override `_guardInitializeOwner => true` itself so `_initializeOwner` reverts on a second
///      call (defence in depth alongside the `initializer` modifier). Fails loudly if a future
///      refactor drops the override and silently re-enables double-initialization.
contract WalletFactory__guardInitializeOwner is WalletFactoryTest {
    function test_guardInitializeOwner_returnsTrue() public {
        WalletFactoryHarness harnessImpl = new WalletFactoryHarness(0.1 ether);
        WalletFactoryHarness harness =
            WalletFactoryHarness(payable(LibClone.deployERC1967(address(harnessImpl))));
        harness.initialize(payable(ADMIN));
        assertTrue(harness.exposed_guardInitializeOwner());
    }

    function test_initialize_secondCallReverts() public {
        // `factory` was already initialized in setUp; a second owner-init attempt must revert.
        vm.expectRevert();
        factory.initialize(payable(BOB));
    }
}
