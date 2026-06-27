// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipFactoryInvariantBase} from "./InvariantBase.sol";
import {QuipFactoryInvariantHandler} from "./Handler.t.sol";

/// @title QuipFactory — Local Invariant Suite (implementation lifecycle)
/// @dev Stateful fuzz campaign over the implementation-lifecycle surface:
///        - vetImplementation
///        - deprecateImplementation
///        - undeprecateImplementation (incl. address-rebind via twin pool)
///        - setCreationFee
///        - setExecuteFee
///
///      All five selectors are cheap (no WOTS+, no proxy deployment), so
///      this suite inherits foundry.toml's defaults rather than scoping
///      down. The audit findings checked here are INVARIANTS.md §7
///      (implementation vetting) and §8 (fee bounding), restated as
///      properties that must hold across arbitrary owner-action sequences.
contract QuipFactory_Local_Invariant is QuipFactoryInvariantBase {
    function setUp() public override {
        super.setUp();
        targetContract(address(handler));

        // Scope the fuzz to lifecycle selectors only. Without this, the
        // runner also picks `initialize` and `acceptFactoryOwnership`,
        // both of which are one-shot setUp helpers — every fuzz hit on
        // them is a guaranteed revert that consumes budget without
        // exploring real state.
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = QuipFactoryInvariantHandler.fuzzVetImplementation.selector;
        selectors[1] = QuipFactoryInvariantHandler.fuzzDeprecateImplementation.selector;
        selectors[2] = QuipFactoryInvariantHandler.fuzzUndeprecateImplementation.selector;
        selectors[3] = QuipFactoryInvariantHandler.fuzzSetCreationFee.selector;
        selectors[4] = QuipFactoryInvariantHandler.fuzzSetExecuteFee.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    /// @dev Audit finding §7 — `latestWalletImpl` must always be either
    ///      `address(0)` (no active impl) or an address whose codehash is
    ///      vetted AND not currently deprecated. This is the load-bearing
    ///      property the factory maintains across three update sites
    ///      (`vetImplementation`, `deprecateImplementation`,
    ///      `undeprecateImplementation`); a stateful sequence is the only
    ///      way to verify the three update rules compose correctly.
    function invariant_latestIsZeroOrNonDeprecatedVetted() public view {
        address latest = factory.latestWalletImpl();
        if (latest == address(0)) return;
        bytes32 ch = latest.codehash;
        uint256 idx = factory.getVettedCodeIndex(ch);
        assertTrue(idx != type(uint256).max, "latest codehash not in vetted set");
        assertEq(factory.vettedWalletImpls(ch), latest, "latest is not the registered impl for its codehash");
        assertFalse(factory.deprecatedImpls(ch), "latest impl's codehash is deprecated");
    }

    /// @dev Audit restatement — the temporal property "a deprecated impl
    ///      never becomes the selected latest without explicit
    ///      undeprecation." Equivalent to the first invariant
    ///      contrapositively, but iterating the full codehash mirror
    ///      surfaces the offending hash on failure rather than just the
    ///      symptom address.
    function invariant_deprecatedNeverSelectedLatest() public view {
        address latest = factory.latestWalletImpl();
        if (latest == address(0)) return;
        uint256 n = handler.everVettedCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 ch = handler.everVettedAt(i);
            if (!factory.deprecatedImpls(ch)) continue;
            assertTrue(factory.vettedWalletImpls(ch) != latest, "deprecated codehash resolves to selected latest");
        }
    }

    /// @dev Audit finding — codehash-to-address provenance. For every
    ///      codehash currently in the vetted set, the registered impl's
    ///      `.codehash` must equal the key it's stored under. Pins the
    ///      `undeprecateImplementation` rebind contract: an address swap
    ///      is allowed, but only to another address with the same
    ///      bytecode (and therefore same codehash). A bug that lets the
    ///      pointer drift to a different codehash would let unvetted
    ///      bytecode masquerade as vetted.
    function invariant_codehashProvenancePreserved() public view {
        uint256 n = factory.getVettedCodeCount();
        for (uint256 i = 0; i < n; i++) {
            bytes32 ch = factory.getVettedCodeAt(i);
            address impl = factory.vettedWalletImpls(ch);
            assertTrue(impl != address(0), "vetted codehash has zero impl");
            assertEq(impl.codehash, ch, "registered impl codehash diverged from key");
        }
    }

    /// @dev INVARIANTS.md §8 — fees are capped at `MAX_FEE` at every
    ///      boundary. Combined with this campaign interleaving fee ops
    ///      against vet/deprecate/undeprecate ops, the other invariants
    ///      double as a non-interaction check: if fee updates could
    ///      corrupt implementation-selection state, one of the other
    ///      properties would fire while this one holds.
    function invariant_feesBoundedByMaxFee() public view {
        uint256 max = factory.MAX_FEE();
        assertLe(factory.creationFee(), max, "creationFee exceeds MAX_FEE");
        assertLe(factory.executeFee(), max, "executeFee exceeds MAX_FEE");
    }

    /// @dev Factory ownership is set in `setUp` and untouched by any
    ///      fuzz selector. A drift implies a broken `onlyOwner` gate or
    ///      a write that escaped the access-control layer.
    function invariant_factoryOwnerStable() public view {
        assertEq(factory.owner(), address(handler), "factory owner drifted");
    }

    /// @dev `EnumerableSetLib` insertion order is preserved across
    ///      deprecate / undeprecate (deprecation is a flag, not a
    ///      removal). The handler's mirror records every successful
    ///      `vetImplementation` plus the seed entry; their counts must
    ///      match the factory's vetted-code length at every boundary.
    function invariant_vettedCodeMonotone() public view {
        assertEq(
            factory.getVettedCodeCount(), handler.everVettedCount(), "vetted code length diverged from handler mirror"
        );
    }
}
