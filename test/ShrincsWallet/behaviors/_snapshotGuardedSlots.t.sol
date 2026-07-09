// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {ShrincsWalletTest} from "../ShrincsWallet.t.sol";

/// @dev Behavior tests for the internal `_snapshotGuardedSlots` (via `exposed_snapshotGuardedSlots`).
///      It captures the eight guarded slots, in the index order the `GuardedSlotTampered(index)`
///      error reports, so the `upgradeToAndCall` verify probe can detect any tampering.
contract ShrincsWallet__snapshotGuardedSlots is ShrincsWalletTest {
    // The eight guarded slots, in index order: owner, ERC-1967 impl, factory, main commitment,
    // erc1271 commitment, keyVersion, nonce, packed leaf-state.
    function _slots() internal pure returns (bytes32[8] memory s) {
        s[0] = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927; // owner (Solady)
        s[1] = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc; // ERC-1967 impl
        s[2] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc00; // quipFactory
        s[3] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc01; // main commitment
        s[4] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc02; // erc1271 commitment
        s[5] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc03; // keyVersion
        s[6] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc04; // nonce
        s[7] = 0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc05; // packed leaf-state
    }

    function test_snapshotGuardedSlots_capturesEachSlotInOrder() public view {
        bytes32[8] memory slots = _slots();
        bytes32[8] memory snapshot = wallet.exposed_snapshotGuardedSlots();
        for (uint256 i = 0; i < 8; i++) {
            assertEq(snapshot[i], vm.load(WALLET, slots[i]), "snapshot[i] mirrors the live slot");
        }
    }

    function test_snapshotGuardedSlots_reflectsLiveValues() public {
        // The installed wallet has a non-zero owner, factory, and main commitment.
        bytes32[8] memory snapshot = wallet.exposed_snapshotGuardedSlots();
        assertEq(snapshot[0], bytes32(uint256(uint160(OWNER))), "slot 0 = owner");
        assertEq(snapshot[3], mainCommitment, "slot 3 = main commitment");
        assertEq(snapshot[4], erc1271Commitment, "slot 4 = erc1271 commitment");
    }

    function test_snapshotGuardedSlots_tracksMutation() public {
        bytes32[8] memory before = wallet.exposed_snapshotGuardedSlots();
        // Bump the keyVersion slot (index 5) directly and re-snapshot.
        bytes32 kvSlot = _slots()[5];
        vm.store(WALLET, kvSlot, bytes32(uint256(before[5]) + 1));
        bytes32[8] memory afterSnap = wallet.exposed_snapshotGuardedSlots();
        assertEq(uint256(afterSnap[5]), uint256(before[5]) + 1, "snapshot tracks the new value");
        // Every other captured slot is unchanged.
        for (uint256 i = 0; i < 8; i++) {
            if (i == 5) continue;
            assertEq(afterSnap[i], before[i], "untouched slots stable");
        }
    }
}
