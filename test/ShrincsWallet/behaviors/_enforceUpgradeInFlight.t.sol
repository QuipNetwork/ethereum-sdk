// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletHarness} from "../../harness/ShrincsWalletHarness.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Unit tests for `_enforceUpgradeInFlight`, the sole gate on `migrate`: it passes exactly
///      when the ERC-1967 slot holds a PREVIOUS implementation (an upgrade into this code is in
///      flight) and refuses the empty slot (bare implementation) and the self-installed slot
///      (direct call on a live wallet).
contract ShrincsWallet__enforceUpgradeInFlight is ShrincsWalletTest {
    // ERC-1967 implementation slot (`uint256(keccak256("eip1967.proxy.implementation")) - 1`).
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    ShrincsWalletHarness internal bare;

    function setUp() public override {
        super.setUp();
        bare = new ShrincsWalletHarness(payable(address(factory)), address(shrincsVerifier));
    }

    function test_setUp() public view override {
        super.test_setUp();
        assertTrue(address(bare).code.length > 0, "bare implementation deployed");
        assertEq(vm.load(address(bare), IMPL_SLOT), bytes32(0), "bare ERC-1967 slot empty");
    }

    /// @dev Mid-upgrade shape: the slot holds a DIFFERENT (previous) implementation.
    function test_exposed_enforceUpgradeInFlight_passesWhenPreviousImplementationInstalled() public {
        vm.store(address(bare), IMPL_SLOT, bytes32(uint256(uint160(address(0xD00D)))));
        bare.exposed_enforceUpgradeInFlight();
    }

    /// @dev Empty slot: a bare implementation (or any non-proxy context) is refused.
    function test_exposed_enforceUpgradeInFlight_revertsWhen_noImplementationInstalled() public {
        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        bare.exposed_enforceUpgradeInFlight();
    }

    /// @dev Self-installed slot: the steady state of a live wallet, where a direct call
    ///      dispatches to the installed code itself.
    function test_exposed_enforceUpgradeInFlight_revertsWhen_selfInstalled() public {
        vm.expectRevert(IShrincsWallet.NotUpgrading.selector);
        wallet.exposed_enforceUpgradeInFlight();
    }
}
