// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusImplementationHarness} from "../../harness/WOTSPlusImplementationHarness.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {WOTSPlusStorage as Storage} from "../../../contracts/deprecated/wots/WOTSPlusStorage.sol";

/// @dev Behaviour tests for `_snapshotGuardedSlots()`. Returns the current
///      SLOAD of the 7 PQ-protected storage slots (owner, ERC-1967 impl,
///      quipFactory, disaster seed/hash, ownership seed/hash) in a fixed order.
///      PQ slot constants are imported from `WOTSPlusStorage` so any drift
///      between the wallet's private literals and the storage library's
///      surfaces here as a snapshot mismatch.
contract WOTSPlusImplementation__snapshotGuardedSlots is WOTSPlusImplementationTest {
    WOTSPlusImplementationHarness public harnessProxy;

    // Solady Ownable owner slot. See dependencies/solady-0.1.26/src/auth/Ownable.sol
    bytes32 constant _OWNER_SLOT = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927;
    // Solady UUPSUpgradeable ERC-1967 implementation slot.
    bytes32 constant _ERC1967_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    function setUp() public override {
        super.setUp();
        WOTSPlusImplementationHarness harnessImpl = new WOTSPlusImplementationHarness(payable(address(factory)));
        vm.prank(ADMIN);
        factory.vetImplementation(address(harnessImpl));

        (WOTSPlus.WinternitzAddress memory pub, bytes32 priv) = _generateKeyPair("h-snap");
        WOTSPlus.WinternitzAddress[] memory rKeys = _generateRecoveryKeys(priv, 10);
        bytes memory payload = _encodeInitPayload(pub, rKeys);

        vm.prank(ALICE);
        address proxyAddr =
            factory.deployLatestWalletProxy{value: INITIAL_DEPOSIT}(keccak256("h-snap-vault"), payable(ALICE), payload);
        harnessProxy = WOTSPlusImplementationHarness(payable(proxyAddr));
    }

    function _loadSlot(bytes32 slot) internal view returns (bytes32 v) {
        v = vm.load(address(harnessProxy), slot);
    }

    function test_exposed_snapshotGuardedSlots_matchesLiveSLOADs() public view {
        bytes32[7] memory snap = harnessProxy.exposed_snapshotGuardedSlots();
        assertEq(snap[0], _loadSlot(_OWNER_SLOT));
        assertEq(snap[1], _loadSlot(_ERC1967_IMPLEMENTATION_SLOT));
        assertEq(snap[2], _loadSlot(Storage._PQ_FACTORY_SLOT));
        assertEq(snap[3], _loadSlot(Storage._DISASTER_KEY_SEED_SLOT));
        assertEq(snap[4], _loadSlot(Storage._DISASTER_KEY_HASH_SLOT));
        assertEq(snap[5], _loadSlot(Storage._OWNERSHIP_KEY_SEED_SLOT));
        assertEq(snap[6], _loadSlot(Storage._OWNERSHIP_KEY_HASH_SLOT));
    }

    function test_exposed_snapshotGuardedSlots_reflectsPostMutation() public {
        // Mutate a guarded slot via vm.store and assert the snapshot picks it up.
        bytes32 newSeed = bytes32(uint256(0xdeadbeef));
        vm.store(address(harnessProxy), Storage._DISASTER_KEY_SEED_SLOT, newSeed);

        bytes32[7] memory snap = harnessProxy.exposed_snapshotGuardedSlots();
        assertEq(snap[3], newSeed);
    }

    function test_exposed_snapshotGuardedSlots_allSevenPositionsDistinct() public view {
        bytes32[7] memory snap = harnessProxy.exposed_snapshotGuardedSlots();
        // Deployed wallet: owner non-zero, impl non-zero, factory non-zero,
        // disaster pair non-zero, ownership pair non-zero. All distinct.
        assertTrue(snap[0] != bytes32(0), "owner zero");
        assertTrue(snap[1] != bytes32(0), "impl zero");
        assertTrue(snap[2] != bytes32(0), "factory zero");
        assertTrue(snap[3] != bytes32(0), "disaster seed zero");
        assertTrue(snap[4] != bytes32(0), "disaster hash zero");
        assertTrue(snap[5] != bytes32(0), "ownership seed zero");
        assertTrue(snap[6] != bytes32(0), "ownership hash zero");
    }
}
