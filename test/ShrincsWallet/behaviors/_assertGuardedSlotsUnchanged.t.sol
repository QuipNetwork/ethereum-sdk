// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IShrincsWallet} from "../../../contracts/shrincs/interfaces/IShrincsWallet.sol";
import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the guarded-slot tamper check used by the `upgradeToAndCall` verify
///      probe. Fully testable now via raw `vm.store` of each of the eight guarded slots. The bitmap
///      mapping is intentionally NOT guarded.
contract ShrincsWallet__assertGuardedSlotsUnchanged is ShrincsWalletTest {
    // The eight guarded slots, in the index order the error reports.
    function _slots() internal pure returns (bytes32[8] memory s) {
        s[0] = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927; // owner (Solady)
        s[1] = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc; // ERC-1967 impl
        s[2] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc00; // walletFactory
        s[3] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc01; // main commitment
        s[4] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc02; // erc1271 commitment
        s[5] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc03; // keyVersion
        s[6] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc04; // nonce
        s[7] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc05; // packed leaf-state
    }

    function test_assertGuardedSlots_noRevertWhenUnchanged() public view {
        bytes32[8] memory snapshot = wallet.exposed_snapshotGuardedSlots();
        // Must not revert when nothing changed.
        wallet.exposed_assertGuardedSlotsUnchanged(snapshot);
    }

    function test_assertGuardedSlots_detectsEachSlotWithCorrectIndex() public {
        bytes32[8] memory slots = _slots();
        for (uint256 i = 0; i < 8; i++) {
            bytes32[8] memory snapshot = wallet.exposed_snapshotGuardedSlots();
            bytes32 orig = vm.load(WALLET, slots[i]);
            vm.store(WALLET, slots[i], bytes32(uint256(orig) ^ 1)); // flip one bit

            vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.GuardedSlotTampered.selector, i));
            wallet.exposed_assertGuardedSlotsUnchanged(snapshot);

            vm.store(WALLET, slots[i], orig); // restore for the next iteration
        }
    }

    function test_assertGuardedSlots_leafConsumeTouchesOnlyCounterSlot() public {
        bytes32[8] memory snapshot = wallet.exposed_snapshotGuardedSlots();
        // Consuming a leaf writes the bitmap mapping (an un-guarded keccak-derived slot) AND bumps
        // the packed `statefulLeavesUsed` counter (the guarded leaf-state word, index 7).
        wallet.harness_markLeafUsed(3);
        // The diff is reported at index 7 only: indices 0-6 are unchanged, so the bitmap mapping
        // write disturbed none of the other guarded slots (it lives outside the guarded set).
        vm.expectRevert(abi.encodeWithSelector(IShrincsWallet.GuardedSlotTampered.selector, 7));
        wallet.exposed_assertGuardedSlotsUnchanged(snapshot);
    }
}
