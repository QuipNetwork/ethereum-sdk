// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Pins the single-source-of-truth invariant for the factory address: the immutable `FACTORY`
///      is authoritative, and the mutable `$.walletFactory` snapshot slot (kept only for the
///      `_SHRINCS_FACTORY_SLOT` guarded-slot layout) is re-established to `FACTORY` on init/migrate so it
///      can never drift from the immutable after an upgrade.
contract ShrincsWallet_walletFactory is ShrincsWalletTest {
    function test_walletFactory_matchesImmutableAfterInit() public view {
        assertEq(wallet.walletFactory(), wallet.FACTORY(), "storage slot == immutable after init");
    }

    function test_walletFactory_reestablishedByMigrate() public {
        // Force the snapshot slot to drift away from the immutable source of truth.
        wallet.harness_setWalletFactory(payable(address(0xDEAD)));
        assertEq(wallet.walletFactory(), address(0xDEAD), "slot drifted for the test");

        // A migration (the post-upgrade re-init hook, run through a REAL signed upgrade)
        // must re-pin it to `FACTORY`.
        (bytes memory payload,) = _freshInitPayload("migrate-fresh-bundle");
        _migrateViaUpgrade(payload);

        assertEq(
            wallet.walletFactory(),
            wallet.FACTORY(),
            "migrate re-establishes the no-drift invariant"
        );
    }
}
