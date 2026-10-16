// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IWOTSPlusImplementation} from "../../../../contracts/deprecated/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";

/// @dev Unit tests for `_enforceUpgradeInFlight`, the sole gate on `migrate`: it passes exactly
///      when the ERC-1967 slot holds a PREVIOUS implementation (an upgrade into this code is in
///      flight) and refuses the empty slot (bare implementation) and the self-installed slot
///      (direct call on a live wallet).
contract WOTSPlusImplementation__enforceUpgradeInFlight is WOTSPlusImplementationTest {
    // ERC-1967 implementation slot (`uint256(keccak256("eip1967.proxy.implementation")) - 1`).
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    WOTSPlusImplementationHarness internal bare;

    function setUp() public override {
        super.setUp();
        bare = new WOTSPlusImplementationHarness(payable(address(factory)));
    }

    /// @dev Mid-upgrade shape: the slot holds a DIFFERENT (previous) implementation.
    function test_exposed_enforceUpgradeInFlight_passesWhenPreviousImplementationInstalled() public {
        vm.store(address(bare), IMPL_SLOT, bytes32(uint256(uint160(address(0xD00D)))));
        bare.exposed_enforceUpgradeInFlight();
    }

    /// @dev Empty slot: a bare implementation (or any non-proxy context) is refused.
    function test_exposed_enforceUpgradeInFlight_revertsWhen_noImplementationInstalled() public {
        vm.expectRevert(IWOTSPlusImplementation.NotUpgrading.selector);
        bare.exposed_enforceUpgradeInFlight();
    }

    /// @dev Self-installed slot: the steady state of a live wallet, where a direct call
    ///      dispatches to the installed code itself.
    function test_exposed_enforceUpgradeInFlight_revertsWhen_selfInstalled() public {
        vm.store(address(bare), IMPL_SLOT, bytes32(uint256(uint160(address(bare)))));
        vm.expectRevert(IWOTSPlusImplementation.NotUpgrading.selector);
        bare.exposed_enforceUpgradeInFlight();
    }
}
