// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryInvariantBase} from "./InvariantBase.sol";
import {WalletFactoryInvariantHandler} from "./Handler.t.sol";

/// @title WalletFactory — Local Invariant Suite (implementation lifecycle)
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
contract WalletFactory_Local_Invariant is WalletFactoryInvariantBase {
    function setUp() public override {
        super.setUp();
        targetContract(address(handler));

        // Scope the fuzz to lifecycle selectors only. Without this, the
        // runner also picks `initialize` and `acceptFactoryOwnership`,
        // both of which are one-shot setUp helpers — every fuzz hit on
        // them is a guaranteed revert that consumes budget without
        // exploring real state.
        bytes4[] memory selectors = new bytes4[](5);
        selectors[0] = WalletFactoryInvariantHandler
            .fuzzVetImplementation
            .selector;
        selectors[1] = WalletFactoryInvariantHandler
            .fuzzDeprecateImplementation
            .selector;
        selectors[2] = WalletFactoryInvariantHandler
            .fuzzUndeprecateImplementation
            .selector;
        selectors[3] = WalletFactoryInvariantHandler
            .fuzzSetCreationFee
            .selector;
        selectors[4] = WalletFactoryInvariantHandler.fuzzSetExecuteFee.selector;
        targetSelector(
            FuzzSelector({addr: address(handler), selectors: selectors})
        );
    }

    function invariant_latestIsMostRecentlyVettedActiveImplementation()
        public
        view
    {
        address expectedLatest;
        for (uint256 i = handler.everVettedCount(); i > 0; i--) {
            bytes32 codehash = handler.everVettedAt(i - 1);
            if (!handler.deprecatedInMirror(codehash)) {
                expectedLatest = handler.implementationInMirror(codehash);
                break;
            }
        }
        assertEq(
            factory.latestWalletImpl(),
            expectedLatest,
            "latest implementation differs from lifecycle mirror"
        );
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
            assertTrue(
                factory.vettedWalletImpls(ch) != latest,
                "deprecated codehash resolves to selected latest"
            );
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
            assertEq(
                impl.codehash,
                ch,
                "registered impl codehash diverged from key"
            );
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
        assertEq(
            factory.creationFee(),
            handler.expectedCreationFee(),
            "creation fee differs from handler mirror"
        );
        assertEq(
            factory.executeFee(),
            handler.expectedExecuteFee(),
            "execute fee differs from handler mirror"
        );
    }

    /// @dev Factory ownership is set in `setUp` and untouched by any
    ///      fuzz selector. A drift implies a broken `onlyOwner` gate or
    ///      a write that escaped the access-control layer.
    function invariant_factoryOwnerStable() public view {
        assertEq(factory.owner(), address(handler), "factory owner drifted");
    }

    function invariant_vettedCodeMatchesMirror() public view {
        uint256 count = handler.everVettedCount();
        assertEq(
            factory.getVettedCodeCount(),
            count,
            "vetted code length diverged from handler mirror"
        );
        for (uint256 i = 0; i < count; i++) {
            bytes32 codehash = handler.everVettedAt(i);
            assertEq(
                factory.getVettedCodeAt(i),
                codehash,
                "vetted code order diverged from handler mirror"
            );
            assertEq(
                factory.getVettedCodeIndex(codehash),
                i,
                "vetted code index diverged from handler mirror"
            );
            assertEq(
                factory.vettedWalletImpls(codehash),
                handler.implementationInMirror(codehash),
                "vetted implementation differs from handler mirror"
            );
            assertEq(
                factory.deprecatedImpls(codehash),
                handler.deprecatedInMirror(codehash),
                "deprecation differs from handler mirror"
            );
        }
    }

    function test_lifecycleActionsReachVettingFallbackRebindAndFeeWrites()
        public
    {
        bytes32 seedCodehash = address(walletImplementation).codehash;

        handler.fuzzVetImplementation(0);
        handler.fuzzVetImplementation(1);
        assertEq(handler.callsVet(), 2);
        bytes32 firstCodehash = handler.everVettedAt(1);
        bytes32 secondCodehash = handler.everVettedAt(2);
        assertEq(factory.latestWalletImpl().codehash, secondCodehash);

        handler.fuzzDeprecateImplementation(2, false);
        assertEq(factory.latestWalletImpl().codehash, firstCodehash);
        handler.fuzzDeprecateImplementation(1, false);
        assertEq(factory.latestWalletImpl().codehash, seedCodehash);
        handler.fuzzDeprecateImplementation(0, false);
        assertEq(factory.latestWalletImpl(), address(0));

        address secondTwin = handler.twinAt(1);
        handler.fuzzUndeprecateImplementation(2, true);
        assertEq(factory.latestWalletImpl(), secondTwin);
        assertEq(factory.vettedWalletImpls(secondCodehash), secondTwin);

        handler.fuzzSetCreationFee(0.04 ether);
        handler.fuzzSetExecuteFee(0.03 ether);
        assertEq(factory.creationFee(), 0.04 ether);
        assertEq(factory.executeFee(), 0.03 ether);
        assertEq(handler.callsDeprecate(), 3);
        assertEq(handler.callsUndeprecate(), 1);
        assertEq(handler.callsSetCreationFee(), 1);
        assertEq(handler.callsSetExecuteFee(), 1);
        assertEq(handler.revertCount(), 0);
    }
}
