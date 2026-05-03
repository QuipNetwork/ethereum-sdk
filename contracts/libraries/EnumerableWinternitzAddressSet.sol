// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @notice Gas-optimized enumerable set for Winternitz address pairs (publicSeed, publicKeyHash).
/// @author quip.network
/// @dev Inspired by Solady's EnumerableSetLib. Each element occupies two storage slots.
/// Uses a lazy-3 optimisation: the first three elements are stored without position mappings.
/// Once a fourth element is added, position mappings are initialised for O(1) lookups.
///
/// Design note: The position mapping key is `keccak256(publicSeed ‖ publicKeyHash)` rather
/// than using `publicKeyHash` alone. While `publicKeyHash` is cryptographically unique in
/// practice, hashing both fields keeps the library general-purpose and avoids coupling it
/// to domain assumptions. The extra keccak256 costs ~36 gas — negligible next to storage
/// operations.
///
/// API note: Functions accept and return `WOTSPlus.WinternitzAddress` structs rather than
/// bare (bytes32, bytes32) pairs. This costs ~12 gas extra per call (2 mloads to
/// destructure) but provides a significantly cleaner interface.
///
/// Storage layout:
///     rootSlot  = keccak256(set.slot ‖ _SLOT_SEED)
///     lazyLen   = sload(not(rootSlot))            // 0 while ≤3 elements
///     element i = (sload(rootSlot+2i), sload(rootSlot+2i+1))
///     position  = sload(keccak256(keyHash ‖ rootSlot))   // 1-indexed
///     keyHash   = keccak256(publicSeed ‖ publicKeyHash)
///
/// Both `publicSeed` and `publicKeyHash` must be non-zero.
/// `publicSeed == 0` is used as the empty-slot sentinel in the lazy phase.
/// Uniqueness is determined by the full pair — two addresses sharing the same
/// `publicSeed` but differing in `publicKeyHash` (or vice versa) are distinct elements.
library EnumerableWinternitzAddressSet {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The index must be less than the length.
    error IndexOutOfBounds();

    /// @dev Both fields of the Winternitz address must be non-zero.
    error ZeroValueWinternitzAddress();

    /// @dev Cannot accommodate a new unique element within the capacity.
    error ExceedsCapacity();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Slot seed for deriving the root slot. Chosen to avoid collisions.
    /// `uint32(bytes4(keccak256("EnumerableWinternitzAddressSet")))`.
    uint256 private constant _SLOT_SEED = 0x3e9f5d6a;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STRUCTS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev An enumerable set of Winternitz address pairs in storage.
    struct WinternitzAddressSet {
        uint256 _spacer;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     GETTERS / SETTERS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the number of elements in the set.
    function length(
        WinternitzAddressSet storage set
    ) internal view returns (uint256 result) {
        bytes32 rootSlot = _rootSlot(set);
        /// @solidity memory-safe-assembly
        assembly {
            let n := sload(not(rootSlot))
            result := shr(1, n)
            for {} iszero(n) {} {
                result := 0
                if iszero(sload(rootSlot)) {
                    break
                }
                result := 1
                if iszero(sload(add(rootSlot, 2))) {
                    break
                }
                result := 2
                if iszero(sload(add(rootSlot, 4))) {
                    break
                }
                result := 3
                break
            }
        }
    }

    /// @dev Returns whether `addr` is in the set.
    function contains(
        WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress memory addr
    ) internal view returns (bool result) {
        bytes32 rootSlot = _rootSlot(set);
        /// @solidity memory-safe-assembly
        assembly {
            let publicSeed := mload(addr)
            let publicKeyHash := mload(add(addr, 0x20))
            for {} 1 {} {
                if iszero(sload(not(rootSlot))) {
                    // Lazy phase: linear scan.
                    result := 1
                    if and(
                        eq(sload(rootSlot), publicSeed),
                        eq(sload(add(rootSlot, 1)), publicKeyHash)
                    ) {
                        break
                    }
                    if and(
                        eq(sload(add(rootSlot, 2)), publicSeed),
                        eq(sload(add(rootSlot, 3)), publicKeyHash)
                    ) {
                        break
                    }
                    if and(
                        eq(sload(add(rootSlot, 4)), publicSeed),
                        eq(sload(add(rootSlot, 5)), publicKeyHash)
                    ) {
                        break
                    }
                    result := 0
                    break
                }
                // Eager phase: position mapping lookup.
                mstore(0x00, publicSeed)
                mstore(0x20, publicKeyHash)
                let keyHash := keccak256(0x00, 0x40)
                mstore(0x00, keyHash)
                mstore(0x20, rootSlot)
                result := iszero(iszero(sload(keccak256(0x00, 0x40))))
                break
            }
        }
    }

    /// @dev Adds `addr` to the set.
    /// Returns whether the pair was not already in the set.
    /// Reverts with `ZeroValueWinternitzAddress` if either field is zero.
    function add(
        WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress memory addr
    ) internal returns (bool result) {
        bytes32 rootSlot = _rootSlot(set);
        /// @solidity memory-safe-assembly
        assembly {
            let publicSeed := mload(addr)
            let publicKeyHash := mload(add(addr, 0x20))
            // Revert if either field is zero.
            if or(iszero(publicSeed), iszero(publicKeyHash)) {
                mstore(0x00, 0xea1c744f) // `ZeroValueWinternitzAddress()`.
                revert(0x1c, 0x04)
            }

            for {
                let n := sload(not(rootSlot))
            } 1 {} {
                // --- Lazy phase ---
                if iszero(n) {
                    // Element 0
                    let s0 := sload(rootSlot)
                    if iszero(s0) {
                        sstore(rootSlot, publicSeed)
                        sstore(add(rootSlot, 1), publicKeyHash)
                        result := 1
                        break
                    }
                    if and(
                        eq(s0, publicSeed),
                        eq(sload(add(rootSlot, 1)), publicKeyHash)
                    ) {
                        break
                    }
                    // Element 1
                    let s1 := sload(add(rootSlot, 2))
                    if iszero(s1) {
                        sstore(add(rootSlot, 2), publicSeed)
                        sstore(add(rootSlot, 3), publicKeyHash)
                        result := 1
                        break
                    }
                    if and(
                        eq(s1, publicSeed),
                        eq(sload(add(rootSlot, 3)), publicKeyHash)
                    ) {
                        break
                    }
                    // Element 2
                    let s2 := sload(add(rootSlot, 4))
                    if iszero(s2) {
                        sstore(add(rootSlot, 4), publicSeed)
                        sstore(add(rootSlot, 5), publicKeyHash)
                        result := 1
                        break
                    }
                    if and(
                        eq(s2, publicSeed),
                        eq(sload(add(rootSlot, 5)), publicKeyHash)
                    ) {
                        break
                    }

                    // All 3 slots occupied and value is new → transition to eager.
                    // Build position mappings for existing elements.
                    mstore(0x20, rootSlot)

                    mstore(0x00, s0)
                    mstore(0x20, sload(add(rootSlot, 1)))
                    let kh := keccak256(0x00, 0x40)
                    mstore(0x00, kh)
                    mstore(0x20, rootSlot)
                    sstore(keccak256(0x00, 0x40), 1) // position 1

                    mstore(0x00, s1)
                    mstore(0x20, sload(add(rootSlot, 3)))
                    kh := keccak256(0x00, 0x40)
                    mstore(0x00, kh)
                    mstore(0x20, rootSlot)
                    sstore(keccak256(0x00, 0x40), 2) // position 2

                    mstore(0x00, s2)
                    mstore(0x20, sload(add(rootSlot, 5)))
                    kh := keccak256(0x00, 0x40)
                    mstore(0x00, kh)
                    mstore(0x20, rootSlot)
                    sstore(keccak256(0x00, 0x40), 3) // position 3

                    // Store new element at index 3 (slots 6,7).
                    sstore(add(rootSlot, 6), publicSeed)
                    sstore(add(rootSlot, 7), publicKeyHash)

                    mstore(0x00, publicSeed)
                    mstore(0x20, publicKeyHash)
                    kh := keccak256(0x00, 0x40)
                    mstore(0x00, kh)
                    mstore(0x20, rootSlot)
                    sstore(keccak256(0x00, 0x40), 4) // position 4

                    // lazyLength = or(1, shl(1, 4)) = 9
                    sstore(not(rootSlot), 9)
                    result := 1
                    break
                }

                // --- Eager phase ---
                mstore(0x00, publicSeed)
                mstore(0x20, publicKeyHash)
                let keyHash := keccak256(0x00, 0x40)
                mstore(0x00, keyHash)
                mstore(0x20, rootSlot)
                let p := keccak256(0x00, 0x40)
                if iszero(sload(p)) {
                    n := shr(1, n)
                    sstore(add(rootSlot, shl(1, n)), publicSeed)
                    sstore(add(rootSlot, add(shl(1, n), 1)), publicKeyHash)
                    sstore(p, add(1, n))
                    sstore(not(rootSlot), or(1, shl(1, add(1, n))))
                    result := 1
                }
                break
            }
        }
    }

    /// @dev Adds `addr` to the set. Returns whether the pair was not already in the set.
    /// Reverts if the set grows bigger than `cap`.
    function add(
        WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress memory addr,
        uint256 cap
    ) internal returns (bool result) {
        if (result = add(set, addr)) {
            if (length(set) > cap) revert ExceedsCapacity();
        }
    }

    /// @dev Removes `addr` from the set.
    /// Returns whether the pair was in the set.
    function remove(
        WinternitzAddressSet storage set,
        WOTSPlus.WinternitzAddress memory addr
    ) internal returns (bool result) {
        bytes32 rootSlot = _rootSlot(set);
        /// @solidity memory-safe-assembly
        assembly {
            let publicSeed := mload(addr)
            let publicKeyHash := mload(add(addr, 0x20))
            for {
                let n := sload(not(rootSlot))
            } 1 {} {
                // --- Lazy phase ---
                if iszero(n) {
                    // Find element by linear scan. Shift subsequent elements down.
                    // Element 0
                    if and(
                        eq(sload(rootSlot), publicSeed),
                        eq(sload(add(rootSlot, 1)), publicKeyHash)
                    ) {
                        // Shift element 1 → 0
                        sstore(rootSlot, sload(add(rootSlot, 2)))
                        sstore(add(rootSlot, 1), sload(add(rootSlot, 3)))
                        // Shift element 2 → 1
                        sstore(add(rootSlot, 2), sload(add(rootSlot, 4)))
                        sstore(add(rootSlot, 3), sload(add(rootSlot, 5)))
                        // Clear element 2
                        sstore(add(rootSlot, 4), 0)
                        sstore(add(rootSlot, 5), 0)
                        result := 1
                        break
                    }
                    // Element 1
                    if and(
                        eq(sload(add(rootSlot, 2)), publicSeed),
                        eq(sload(add(rootSlot, 3)), publicKeyHash)
                    ) {
                        // Shift element 2 → 1
                        sstore(add(rootSlot, 2), sload(add(rootSlot, 4)))
                        sstore(add(rootSlot, 3), sload(add(rootSlot, 5)))
                        // Clear element 2
                        sstore(add(rootSlot, 4), 0)
                        sstore(add(rootSlot, 5), 0)
                        result := 1
                        break
                    }
                    // Element 2
                    if and(
                        eq(sload(add(rootSlot, 4)), publicSeed),
                        eq(sload(add(rootSlot, 5)), publicKeyHash)
                    ) {
                        sstore(add(rootSlot, 4), 0)
                        sstore(add(rootSlot, 5), 0)
                        result := 1
                        break
                    }
                    break
                }

                // --- Eager phase ---
                mstore(0x00, publicSeed)
                mstore(0x20, publicKeyHash)
                let keyHash := keccak256(0x00, 0x40)
                mstore(0x00, keyHash)
                mstore(0x20, rootSlot)
                let p := keccak256(0x00, 0x40)
                let position := sload(p)
                if iszero(position) {
                    break
                }

                n := sub(shr(1, n), 1) // last index
                let removedIdx := sub(position, 1)
                if iszero(eq(removedIdx, n)) {
                    // Swap last element into the removed position.
                    let lastOff := shl(1, n)
                    let lastSeed := sload(add(rootSlot, lastOff))
                    let lastHash := sload(add(rootSlot, add(lastOff, 1)))
                    let removedOff := shl(1, removedIdx)
                    sstore(add(rootSlot, removedOff), lastSeed)
                    sstore(add(rootSlot, add(removedOff, 1)), lastHash)
                    // Update position mapping for swapped element.
                    mstore(0x00, lastSeed)
                    mstore(0x20, lastHash)
                    let lastKeyHash := keccak256(0x00, 0x40)
                    mstore(0x00, lastKeyHash)
                    mstore(0x20, rootSlot)
                    sstore(keccak256(0x00, 0x40), position)
                }
                // Clear last element slots.
                let lastOff2 := shl(1, n)
                sstore(add(rootSlot, lastOff2), 0)
                sstore(add(rootSlot, add(lastOff2, 1)), 0)
                // Clear position mapping and update length.
                sstore(p, 0)
                sstore(not(rootSlot), or(shl(1, n), 1))
                result := 1
                break
            }
        }
    }

    /// @dev Drains all elements from `set` in a single pass. Returns the
    ///      number of elements cleared so the caller can assert the wipe was
    ///      total (e.g., matches a pre-call `length()`).
    ///
    ///      Cheaper than n calls to `remove(set, at(0))` because it skips the
    ///      per-iteration swap-and-pop dance, the redundant `_rootSlot`
    ///      recomputation, and the bounds-check / length SLOADs each call
    ///      site does. After the call the length slot is reset to the
    ///      lazy-phase marker (0); a set previously in eager phase will
    ///      operate as a fresh lazy-phase set on the next add.
    ///
    ///      Lazy phase (length slot == 0): the position mapping was never
    ///      written, so this just zeroes the up-to-3 in-place element slots.
    ///      Eager phase: zeroes each populated element slot and its
    ///      corresponding position-mapping entry, then resets the length
    ///      slot.
    function clear(
        WinternitzAddressSet storage set
    ) internal returns (uint256 cleared) {
        bytes32 rootSlot = _rootSlot(set);
        /// @solidity memory-safe-assembly
        assembly {
            let n := sload(not(rootSlot))
            switch iszero(n)
            case 1 {
                // Lazy phase — count populated slots while zeroing them.
                if iszero(iszero(sload(rootSlot))) {
                    sstore(rootSlot, 0)
                    sstore(add(rootSlot, 1), 0)
                    cleared := 1
                    if iszero(iszero(sload(add(rootSlot, 2)))) {
                        sstore(add(rootSlot, 2), 0)
                        sstore(add(rootSlot, 3), 0)
                        cleared := 2
                        if iszero(iszero(sload(add(rootSlot, 4)))) {
                            sstore(add(rootSlot, 4), 0)
                            sstore(add(rootSlot, 5), 0)
                            cleared := 3
                        }
                    }
                }
            }
            default {
                // Eager phase — iterate, zero element slots + position mapping.
                let len := shr(1, n)
                for {
                    let i := 0
                } lt(i, len) {
                    i := add(i, 1)
                } {
                    let off := shl(1, i)
                    let pSeed := sload(add(rootSlot, off))
                    let pHash := sload(add(rootSlot, add(off, 1)))
                    sstore(add(rootSlot, off), 0)
                    sstore(add(rootSlot, add(off, 1)), 0)
                    mstore(0x00, pSeed)
                    mstore(0x20, pHash)
                    let keyHash := keccak256(0x00, 0x40)
                    mstore(0x00, keyHash)
                    mstore(0x20, rootSlot)
                    sstore(keccak256(0x00, 0x40), 0)
                }
                // Reset length slot to the lazy-phase marker.
                sstore(not(rootSlot), 0)
                cleared := len
            }
        }
    }

    /// @dev Returns the pair at index `i` in the set. Reverts if `i` is out-of-bounds.
    function at(
        WinternitzAddressSet storage set,
        uint256 i
    ) internal view returns (WOTSPlus.WinternitzAddress memory addr) {
        bytes32 rootSlot = _rootSlot(set);
        /// @solidity memory-safe-assembly
        assembly {
            let off := add(rootSlot, shl(1, i))
            mstore(addr, sload(off))
            mstore(add(addr, 0x20), sload(add(off, 1)))
        }
        if (i >= length(set)) revert IndexOutOfBounds();
    }

    /// @dev Returns all pairs in the set.
    /// Note: This can consume more gas than the block gas limit for large sets.
    function values(
        WinternitzAddressSet storage set
    ) internal view returns (WOTSPlus.WinternitzAddress[] memory result) {
        bytes32 rootSlot = _rootSlot(set);
        /// @solidity memory-safe-assembly
        assembly {
            let n := sload(not(rootSlot))

            // Determine count.
            for {} 1 {} {
                if iszero(n) {
                    n := 0
                    if iszero(sload(rootSlot)) {
                        break
                    }
                    n := 1
                    if iszero(sload(add(rootSlot, 2))) {
                        break
                    }
                    n := 2
                    if iszero(sload(add(rootSlot, 4))) {
                        break
                    }
                    n := 3
                    break
                }
                n := shr(1, n)
                break
            }

            // Allocate array: length word + n pointer slots + n structs (64 bytes each).
            result := mload(0x40)
            mstore(result, n)
            let ptrs := add(result, 0x20)
            let structs := add(ptrs, shl(5, n))

            // Populate.
            for {
                let i := 0
            } lt(i, n) {
                i := add(i, 1)
            } {
                let off := add(rootSlot, shl(1, i))
                let s := add(structs, mul(i, 0x40))
                mstore(add(ptrs, shl(5, i)), s)
                mstore(s, sload(off))
                mstore(add(s, 0x20), sload(add(off, 1)))
            }

            // Update free memory pointer.
            mstore(0x40, add(structs, mul(n, 0x40)))
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the root slot derived from the set's storage slot.
    function _rootSlot(
        WinternitzAddressSet storage s
    ) private pure returns (bytes32 r) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x04, _SLOT_SEED)
            mstore(0x00, s.slot)
            r := keccak256(0x00, 0x24)
        }
    }
}
