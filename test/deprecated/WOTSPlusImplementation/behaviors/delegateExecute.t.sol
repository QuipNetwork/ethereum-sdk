// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlusImplementationTest} from "../WOTSPlusImplementation.t.sol";
import {WOTSPlusStorage as Storage} from "../../../../contracts/deprecated/wots/WOTSPlusStorage.sol";

/// @dev Benign delegate — writes to a slot outside the 7 guarded slots.
///      Picks an arbitrary high slot (not aliased to owner/impl/factory/
///      disaster/ownership) so the `delegateExecuteGuard` snapshot check does
///      not fire.
contract BenignDelegate {
    fallback() external payable {
        /// @solidity memory-safe-assembly
        assembly {
            sstore(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, 0x01)
        }
    }
}

/// @dev Rogue delegate — SSTOREs to the disaster-recovery-key seed slot, which
///      is one of the 7 snapshotted-and-checked slots. The post-call assert
///      must fire and revert. Slot loaded from `WOTSPlusStorage` via a local
///      variable because Yul rejects direct cross-library constant references.
contract RogueDelegate_WritesDisasterSlot {
    fallback() external payable {
        bytes32 slot = Storage._DISASTER_KEY_SEED_SLOT;
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, 0xdeadbeef)
        }
    }
}

/// @dev Rogue delegate — SSTOREs to the ownership-key hash slot (distinct branch
///      of the guard's 7-slot check).
contract RogueDelegate_WritesOwnershipSlot {
    fallback() external payable {
        bytes32 slot = Storage._OWNERSHIP_KEY_HASH_SLOT;
        /// @solidity memory-safe-assembly
        assembly {
            sstore(slot, 0xcafef00d)
        }
    }
}

/// @dev Behaviour tests for the ERC-4337 `delegateExecute(address, bytes)`
///      override. Guarded by `onlyEntryPoint` and `delegateExecuteGuard` (our
///      override of Solady's guard snapshots the 7 PQ-protected slots pre-call
///      and asserts them post-call).
contract WOTSPlusImplementation_delegateExecute is WOTSPlusImplementationTest {
    BenignDelegate internal benign;
    RogueDelegate_WritesDisasterSlot internal rogueDisaster;
    RogueDelegate_WritesOwnershipSlot internal rogueOwnership;

    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    function setUp() public override {
        super.setUp();
        benign = new BenignDelegate();
        rogueDisaster = new RogueDelegate_WritesDisasterSlot();
        rogueOwnership = new RogueDelegate_WritesOwnershipSlot();
        vm.deal(ENTRY_POINT, 10 ether);
    }

    function test_delegateExecute_succeedsWithBenignDelegate() public {
        vm.prank(ENTRY_POINT);
        wallet.delegateExecute(address(benign), hex"");
    }

    function test_delegateExecute_collectsExecuteFee() public {
        vm.prank(ADMIN);
        factory.setExecuteFee(EXECUTE_FEE);

        uint256 walletBefore = address(wallet).balance;
        uint256 factoryBefore = address(factory).balance;

        vm.prank(ENTRY_POINT);
        wallet.delegateExecute(address(benign), hex"");

        assertEq(address(wallet).balance, walletBefore - EXECUTE_FEE);
        assertEq(address(factory).balance, factoryBefore + EXECUTE_FEE);
    }

    function test_delegateExecute_revertsWhen_callerNotEntryPoint() public {
        vm.prank(ALICE);
        vm.expectRevert(); // Solady Unauthorized
        wallet.delegateExecute(address(benign), hex"");
    }

    function test_delegateExecute_revertsWhen_delegateMutatesDisasterSlot() public {
        vm.prank(ENTRY_POINT);
        vm.expectRevert(); // Empty-bytes revert from the guard
        wallet.delegateExecute(address(rogueDisaster), hex"");
    }

    function test_delegateExecute_revertsWhen_delegateMutatesOwnershipSlot() public {
        vm.prank(ENTRY_POINT);
        vm.expectRevert();
        wallet.delegateExecute(address(rogueOwnership), hex"");
    }
}
