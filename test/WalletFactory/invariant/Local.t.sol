// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WalletFactoryInvariantBase} from "./InvariantBase.sol";
import {WalletFactoryInvariantHandler} from "./Handler.t.sol";

contract WalletFactory_Local_Invariant is WalletFactoryInvariantBase {
    function setUp() public override {
        super.setUp();
        targetContract(address(handler));

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

    function invariant_deprecatedNeverSelectedLatest() public view {
        address latest = factory.latestWalletImpl();
        if (latest == address(0)) return;
        uint256 vettedCount = handler.everVettedCount();
        for (uint256 i = 0; i < vettedCount; i++) {
            bytes32 codehash = handler.everVettedAt(i);
            if (!factory.deprecatedImpls(codehash)) continue;
            assertTrue(
                factory.vettedWalletImpls(codehash) != latest,
                "deprecated codehash resolves to selected latest"
            );
        }
    }

    function invariant_codehashProvenancePreserved() public view {
        uint256 vettedCount = factory.getVettedCodeCount();
        for (uint256 i = 0; i < vettedCount; i++) {
            bytes32 codehash = factory.getVettedCodeAt(i);
            address implementation = factory.vettedWalletImpls(codehash);
            assertTrue(
                implementation != address(0),
                "vetted codehash has zero impl"
            );
            assertEq(
                implementation.codehash,
                codehash,
                "registered impl codehash diverged from key"
            );
        }
    }

    function invariant_feesBoundedByMaxFee() public view {
        uint256 maxFee = factory.MAX_FEE();
        assertLe(factory.creationFee(), maxFee, "creationFee exceeds MAX_FEE");
        assertLe(factory.executeFee(), maxFee, "executeFee exceeds MAX_FEE");
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

    function invariant_factoryOwnerStable() public view {
        assertEq(factory.owner(), address(handler), "factory owner drifted");
    }

    function invariant_lifecycleActionsMatchExpectedOutcomes() public view {
        assertEq(
            handler.unexpectedSuccesses(),
            0,
            "invalid lifecycle call succeeded"
        );
        assertEq(
            handler.unexpectedFailures(),
            0,
            "valid lifecycle call reverted"
        );
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
        invariant_lifecycleActionsMatchExpectedOutcomes();
    }
}
