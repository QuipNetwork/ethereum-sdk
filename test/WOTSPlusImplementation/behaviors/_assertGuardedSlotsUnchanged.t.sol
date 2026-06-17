// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {IWOTSPlusImplementation} from "../../../contracts/wots/interfaces/IWOTSPlusImplementation.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {WOTSPlusStorage as Storage} from "../../../contracts/wots/WOTSPlusStorage.sol";

/// @dev Behaviour tests for `_assertGuardedSlotsUnchanged(snapshot)`.
///      Compares a prior snapshot against the current SLOADs of the 7 guarded
///      slots; no-op if all match, reverts with `GuardedSlotTampered(idx)`
///      otherwise. This file exercises one revert branch per slot (7 total),
///      verifies the slot index matches the documented mapping, and covers
///      the happy path plus a "no pre-read" edge case.
///
///      PQ slot constants are imported from `WOTSPlusStorage` so any drift
///      between the wallet's private literals (used inside its
///      `delegateExecuteGuard`'s pre/post snapshot Yul) and the storage
///      library's surfaces here as a missing tamper detection.
contract WOTSPlusImplementation__assertGuardedSlotsUnchanged is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    bytes32 constant _OWNER_SLOT =
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927;
    bytes32 constant _ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function setUp() public override {
        super.setUp();
        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(
            payable(address(factory))
        );
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (
            WOTSPlus.WinternitzAddress memory pub,
            bytes32 priv
        ) = _generateKeyPair("h-agsu");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(
            priv,
            10
        );
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr = factory.deployLatestWalletProxy{
            value: INITIAL_DEPOSIT
        }(keccak256("h-agsu-vault"), payable(ALICE), payload);
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    function _snap() internal view returns (bytes32[7] memory) {
        return harnessProxy.exposed_snapshotGuardedSlots();
    }

    function test_exposed_assertGuardedSlotsUnchanged_happyPath() public view {
        harnessProxy.exposed_assertGuardedSlotsUnchanged(_snap());
    }

    function test_exposed_assertGuardedSlotsUnchanged_revertsWhen_ownerChanged()
        public
    {
        bytes32[7] memory s = _snap();
        vm.store(address(harnessProxy), _OWNER_SLOT, bytes32(uint256(0xaaaa)));
        vm.expectRevert(
            abi.encodeWithSelector(
                IWOTSPlusImplementation.GuardedSlotTampered.selector,
                uint8(0)
            )
        );
        harnessProxy.exposed_assertGuardedSlotsUnchanged(s);
    }

    // Cannot mutate the proxy's impl slot in-place — the next delegatecall-
    // through-proxy would resolve to the mutated address and fail opaquely.
    // Instead, exercise this branch against a bare harness where the impl slot
    // is plain storage with no live role.
    function test_exposed_assertGuardedSlotsUnchanged_revertsWhen_implChanged()
        public
    {
        WOTSPlusImplementationHarness bare = new WOTSPlusImplementationHarness(
            payable(address(factory))
        );
        bytes32[7] memory s = bare.exposed_snapshotGuardedSlots();
        vm.store(
            address(bare),
            _ERC1967_IMPLEMENTATION_SLOT,
            bytes32(uint256(0xbbbb))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IWOTSPlusImplementation.GuardedSlotTampered.selector,
                uint8(1)
            )
        );
        bare.exposed_assertGuardedSlotsUnchanged(s);
    }

    function test_exposed_assertGuardedSlotsUnchanged_revertsWhen_factoryChanged()
        public
    {
        bytes32[7] memory s = _snap();
        vm.store(
            address(harnessProxy),
            Storage._PQ_FACTORY_SLOT,
            bytes32(uint256(0xcccc))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IWOTSPlusImplementation.GuardedSlotTampered.selector,
                uint8(2)
            )
        );
        harnessProxy.exposed_assertGuardedSlotsUnchanged(s);
    }

    function test_exposed_assertGuardedSlotsUnchanged_revertsWhen_disasterSeedChanged()
        public
    {
        bytes32[7] memory s = _snap();
        vm.store(
            address(harnessProxy),
            Storage._DISASTER_KEY_SEED_SLOT,
            bytes32(uint256(0xdddd))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IWOTSPlusImplementation.GuardedSlotTampered.selector,
                uint8(3)
            )
        );
        harnessProxy.exposed_assertGuardedSlotsUnchanged(s);
    }

    function test_exposed_assertGuardedSlotsUnchanged_revertsWhen_disasterHashChanged()
        public
    {
        bytes32[7] memory s = _snap();
        vm.store(
            address(harnessProxy),
            Storage._DISASTER_KEY_HASH_SLOT,
            bytes32(uint256(0xeeee))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IWOTSPlusImplementation.GuardedSlotTampered.selector,
                uint8(4)
            )
        );
        harnessProxy.exposed_assertGuardedSlotsUnchanged(s);
    }

    function test_exposed_assertGuardedSlotsUnchanged_revertsWhen_ownershipSeedChanged()
        public
    {
        bytes32[7] memory s = _snap();
        vm.store(
            address(harnessProxy),
            Storage._OWNERSHIP_KEY_SEED_SLOT,
            bytes32(uint256(0xffff))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IWOTSPlusImplementation.GuardedSlotTampered.selector,
                uint8(5)
            )
        );
        harnessProxy.exposed_assertGuardedSlotsUnchanged(s);
    }

    function test_exposed_assertGuardedSlotsUnchanged_revertsWhen_ownershipHashChanged()
        public
    {
        bytes32[7] memory s = _snap();
        vm.store(
            address(harnessProxy),
            Storage._OWNERSHIP_KEY_HASH_SLOT,
            bytes32(uint256(0x1234))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IWOTSPlusImplementation.GuardedSlotTampered.selector,
                uint8(6)
            )
        );
        harnessProxy.exposed_assertGuardedSlotsUnchanged(s);
    }

    // Supplying a zero-filled snapshot against a live, initialised wallet
    // should revert on the very first comparison (owner ≠ 0) → index 0.
    function test_exposed_assertGuardedSlotsUnchanged_revertsWhen_snapshotAllZero()
        public
    {
        bytes32[7] memory zero;
        vm.expectRevert(
            abi.encodeWithSelector(
                IWOTSPlusImplementation.GuardedSlotTampered.selector,
                uint8(0)
            )
        );
        harnessProxy.exposed_assertGuardedSlotsUnchanged(zero);
    }
}
