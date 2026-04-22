// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {QuipWalletTest} from "../QuipWallet.t.sol";

/// @dev Behaviour tests for the ERC-4337 `storageStore(bytes32, bytes32)`
///      override. Guarded by `onlyEntryPoint` and our `storageStoreGuard`,
///      which blocks writes to 7 PQ-protected slots: owner, ERC-1967 impl,
///      quipFactory, disaster seed/hash, ownership seed/hash. All other slots
///      are permitted (the three keyset root/element slots are deliberately
///      NOT guarded — the disaster / ownership keys are the rescue path if a
///      keyset is corrupted).
contract QuipWallet_storageStore is QuipWalletTest {
    address constant ENTRY_POINT =
        0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    bytes32 constant _OWNER_SLOT =
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927;
    bytes32 constant _ERC1967_IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 constant _PQ_FACTORY_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;
    bytes32 constant _DISASTER_KEY_SEED_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf701;
    bytes32 constant _DISASTER_KEY_HASH_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf702;
    bytes32 constant _OWNERSHIP_KEY_SEED_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf703;
    bytes32 constant _OWNERSHIP_KEY_HASH_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf704;

    bytes32 constant NONGUARDED_SLOT =
        0xbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef;

    function setUp() public override {
        super.setUp();
        vm.deal(ENTRY_POINT, 10 ether);
    }

    function _expectGuardedRevertOnStore(bytes32 slot) internal {
        vm.prank(ENTRY_POINT);
        vm.expectRevert(); // plain revert via `revert(codesize(), 0x00)`
        wallet.storageStore(slot, bytes32(uint256(0xdead)));
    }

    /*──────────────────────────── happy path ────────────────────────────*/

    function test_storageStore_succeedsOnNonGuardedSlot() public {
        bytes32 value = bytes32(uint256(0x7777));
        vm.prank(ENTRY_POINT);
        wallet.storageStore(NONGUARDED_SLOT, value);

        assertEq(vm.load(address(wallet), NONGUARDED_SLOT), value);
    }

    /*──────────────────────── access control ────────────────────────────*/

    function test_storageStore_revertsWhen_callerNotEntryPoint() public {
        vm.prank(ALICE);
        vm.expectRevert(); // Solady Unauthorized
        wallet.storageStore(NONGUARDED_SLOT, bytes32(uint256(1)));
    }

    /*───────────────────────── guarded slot reverts ─────────────────────*/

    function test_storageStore_revertsWhen_writeToOwnerSlot() public {
        _expectGuardedRevertOnStore(_OWNER_SLOT);
    }

    function test_storageStore_revertsWhen_writeToImplementationSlot() public {
        _expectGuardedRevertOnStore(_ERC1967_IMPLEMENTATION_SLOT);
    }

    function test_storageStore_revertsWhen_writeToFactorySlot() public {
        _expectGuardedRevertOnStore(_PQ_FACTORY_SLOT);
    }

    function test_storageStore_revertsWhen_writeToDisasterSeedSlot() public {
        _expectGuardedRevertOnStore(_DISASTER_KEY_SEED_SLOT);
    }

    function test_storageStore_revertsWhen_writeToDisasterHashSlot() public {
        _expectGuardedRevertOnStore(_DISASTER_KEY_HASH_SLOT);
    }

    function test_storageStore_revertsWhen_writeToOwnershipSeedSlot() public {
        _expectGuardedRevertOnStore(_OWNERSHIP_KEY_SEED_SLOT);
    }

    function test_storageStore_revertsWhen_writeToOwnershipHashSlot() public {
        _expectGuardedRevertOnStore(_OWNERSHIP_KEY_HASH_SLOT);
    }
}
