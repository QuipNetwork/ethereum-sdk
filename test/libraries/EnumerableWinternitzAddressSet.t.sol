// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {LibPRNG} from "solady-0.1.26/src/utils/LibPRNG.sol";
import {LibSort} from "solady-0.1.26/src/utils/LibSort.sol";
import {EnumerableWinternitzAddressSet} from "contracts/wots/EnumerableWinternitzAddressSet.sol";

/// @dev Harness that exposes library functions as external calls for revert testing.
contract SetHarness {
    using EnumerableWinternitzAddressSet for EnumerableWinternitzAddressSet.WinternitzAddressSet;

    EnumerableWinternitzAddressSet.WinternitzAddressSet private s;
    EnumerableWinternitzAddressSet.WinternitzAddressSet private s2;

    function add(WOTSPlus.WinternitzAddress memory addr) external returns (bool) {
        return s.add(addr);
    }

    function addCapped(WOTSPlus.WinternitzAddress memory addr, uint256 cap) external returns (bool) {
        return s.add(addr, cap);
    }

    function remove(WOTSPlus.WinternitzAddress memory addr) external returns (bool) {
        return s.remove(addr);
    }

    function contains(WOTSPlus.WinternitzAddress memory addr) external view returns (bool) {
        return s.contains(addr);
    }

    function length() external view returns (uint256) {
        return s.length();
    }

    function at(uint256 i) external view returns (WOTSPlus.WinternitzAddress memory) {
        return s.at(i);
    }

    function values() external view returns (WOTSPlus.WinternitzAddress[] memory) {
        return s.values();
    }

    function clear() external returns (uint256) {
        return s.clear();
    }

    // --- Second set for collision testing ---

    function add2(WOTSPlus.WinternitzAddress memory addr) external returns (bool) {
        return s2.add(addr);
    }

    function contains2(WOTSPlus.WinternitzAddress memory addr) external view returns (bool) {
        return s2.contains(addr);
    }

    function length2() external view returns (uint256) {
        return s2.length();
    }

    function clear2() external returns (uint256) {
        return s2.clear();
    }
}

contract EnumerableWinternitzAddressSetTest is Test {
    using LibPRNG for LibPRNG.PRNG;
    using LibSort for uint256[];

    SetHarness private h;

    WOTSPlus.WinternitzAddress A1 = WOTSPlus.WinternitzAddress(bytes32(uint256(0xaa)), bytes32(uint256(0xbb)));
    WOTSPlus.WinternitzAddress A2 = WOTSPlus.WinternitzAddress(bytes32(uint256(0xcc)), bytes32(uint256(0xdd)));
    WOTSPlus.WinternitzAddress A3 = WOTSPlus.WinternitzAddress(bytes32(uint256(0xee)), bytes32(uint256(0xff)));
    WOTSPlus.WinternitzAddress A4 = WOTSPlus.WinternitzAddress(bytes32(uint256(0x11)), bytes32(uint256(0x22)));
    WOTSPlus.WinternitzAddress A5 = WOTSPlus.WinternitzAddress(bytes32(uint256(0x33)), bytes32(uint256(0x44)));

    WOTSPlus.WinternitzAddress ZERO_SEED = WOTSPlus.WinternitzAddress(bytes32(0), bytes32(uint256(0xbb)));
    WOTSPlus.WinternitzAddress ZERO_HASH = WOTSPlus.WinternitzAddress(bytes32(uint256(0xaa)), bytes32(0));
    WOTSPlus.WinternitzAddress ZERO_BOTH = WOTSPlus.WinternitzAddress(bytes32(0), bytes32(0));

    function setUp() public {
        h = new SetHarness();
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   STORAGE COLLISION                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_noStorageCollision_lazy() public {
        h.add(A1);
        assertFalse(h.contains2(A1));
        h.add2(A2);
        assertTrue(h.contains(A1));
        assertFalse(h.contains(A2));
        assertFalse(h.contains2(A1));
        assertTrue(h.contains2(A2));
        assertEq(h.length(), 1);
        assertEq(h.length2(), 1);
    }

    function test_noStorageCollision_eager() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.add2(A5);
        assertFalse(h.contains2(A1));
        assertTrue(h.contains2(A5));
        assertFalse(h.contains(A5));
        assertEq(h.length(), 4);
        assertEq(h.length2(), 1);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         LENGTH                                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_length_empty() public view {
        assertEq(h.length(), 0);
    }

    function test_length_lazy() public {
        h.add(A1);
        assertEq(h.length(), 1);
        h.add(A2);
        assertEq(h.length(), 2);
        h.add(A3);
        assertEq(h.length(), 3);
    }

    function test_length_eager() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        assertEq(h.length(), 4);
        h.add(A5);
        assertEq(h.length(), 5);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ADD                                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_add_single() public {
        assertTrue(h.add(A1));
        assertEq(h.length(), 1);
        assertTrue(h.contains(A1));
    }

    function test_add_duplicate_lazy() public {
        assertTrue(h.add(A1));
        assertFalse(h.add(A1));
        assertEq(h.length(), 1);
    }

    function test_add_duplicate_eager() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        assertFalse(h.add(A1));
        assertFalse(h.add(A4));
        assertEq(h.length(), 4);
    }

    function test_add_transitionsToEager() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        assertTrue(h.add(A4));
        assertEq(h.length(), 4);
        assertTrue(h.contains(A1));
        assertTrue(h.contains(A2));
        assertTrue(h.contains(A3));
        assertTrue(h.contains(A4));
    }

    function test_add_sameSeedDifferentHash_lazy() public {
        WOTSPlus.WinternitzAddress memory a = WOTSPlus.WinternitzAddress(A1.publicSeed, A2.publicKeyHash);
        assertTrue(h.add(A1));
        assertTrue(h.add(a));
        assertEq(h.length(), 2);
        assertTrue(h.contains(A1));
        assertTrue(h.contains(a));
    }

    function test_add_differentSeedSameHash_lazy() public {
        WOTSPlus.WinternitzAddress memory a = WOTSPlus.WinternitzAddress(A2.publicSeed, A1.publicKeyHash);
        assertTrue(h.add(A1));
        assertTrue(h.add(a));
        assertEq(h.length(), 2);
        assertTrue(h.contains(A1));
        assertTrue(h.contains(a));
    }

    function test_add_sameSeedDifferentHash_eager() public {
        WOTSPlus.WinternitzAddress memory a = WOTSPlus.WinternitzAddress(A1.publicSeed, A2.publicKeyHash);
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        assertTrue(h.add(a));
        assertEq(h.length(), 5);
        assertTrue(h.contains(A1));
        assertTrue(h.contains(a));
    }

    function test_add_revertsWhen_zeroSeed() public {
        vm.expectRevert(EnumerableWinternitzAddressSet.ZeroValueWinternitzAddress.selector);
        h.add(ZERO_SEED);
    }

    function test_add_revertsWhen_zeroHash() public {
        vm.expectRevert(EnumerableWinternitzAddressSet.ZeroValueWinternitzAddress.selector);
        h.add(ZERO_HASH);
    }

    function test_add_revertsWhen_bothZero() public {
        vm.expectRevert(EnumerableWinternitzAddressSet.ZeroValueWinternitzAddress.selector);
        h.add(ZERO_BOTH);
    }

    function test_add_capped() public {
        assertTrue(h.addCapped(A1, 3));
        assertTrue(h.addCapped(A2, 3));
        assertTrue(h.addCapped(A3, 3));
        vm.expectRevert(EnumerableWinternitzAddressSet.ExceedsCapacity.selector);
        h.addCapped(A4, 3);
    }

    function test_add_capped_duplicateDoesNotRevert() public {
        h.addCapped(A1, 2);
        h.addCapped(A2, 2);
        assertFalse(h.addCapped(A1, 2));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONTAINS                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_contains_empty() public view {
        assertFalse(h.contains(A1));
    }

    function test_contains_lazy() public {
        h.add(A1);
        h.add(A2);
        assertTrue(h.contains(A1));
        assertTrue(h.contains(A2));
        assertFalse(h.contains(A3));
    }

    function test_contains_eager() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        assertTrue(h.contains(A1));
        assertTrue(h.contains(A4));
        assertFalse(h.contains(A5));
    }

    function test_contains_sameSeedDifferentHash() public {
        WOTSPlus.WinternitzAddress memory a = WOTSPlus.WinternitzAddress(A1.publicSeed, A2.publicKeyHash);
        h.add(A1);
        assertFalse(h.contains(a));
    }

    function test_contains_differentSeedSameHash() public {
        WOTSPlus.WinternitzAddress memory a = WOTSPlus.WinternitzAddress(A2.publicSeed, A1.publicKeyHash);
        h.add(A1);
        assertFalse(h.contains(a));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         REMOVE                                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_remove_nonExistent() public {
        assertFalse(h.remove(A1));
    }

    function test_remove_nonExistent_eager() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        assertFalse(h.remove(A5));
        assertEq(h.length(), 4);
    }

    function test_remove_lazy_single() public {
        h.add(A1);
        assertTrue(h.remove(A1));
        assertEq(h.length(), 0);
        assertFalse(h.contains(A1));
    }

    function test_remove_lazy_first() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        assertTrue(h.remove(A1));
        assertEq(h.length(), 2);
        assertFalse(h.contains(A1));
        WOTSPlus.WinternitzAddress memory r0 = h.at(0);
        assertEq(r0.publicSeed, A2.publicSeed);
        assertEq(r0.publicKeyHash, A2.publicKeyHash);
        WOTSPlus.WinternitzAddress memory r1 = h.at(1);
        assertEq(r1.publicSeed, A3.publicSeed);
        assertEq(r1.publicKeyHash, A3.publicKeyHash);
    }

    function test_remove_lazy_middle() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        assertTrue(h.remove(A2));
        assertEq(h.length(), 2);
        WOTSPlus.WinternitzAddress memory r0 = h.at(0);
        assertEq(r0.publicSeed, A1.publicSeed);
        assertEq(r0.publicKeyHash, A1.publicKeyHash);
        WOTSPlus.WinternitzAddress memory r1 = h.at(1);
        assertEq(r1.publicSeed, A3.publicSeed);
        assertEq(r1.publicKeyHash, A3.publicKeyHash);
    }

    function test_remove_lazy_last() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        assertTrue(h.remove(A3));
        assertEq(h.length(), 2);
        assertTrue(h.contains(A1));
        assertTrue(h.contains(A2));
    }

    function test_remove_lazy_twoElements_removeFirst() public {
        h.add(A1);
        h.add(A2);
        h.remove(A1);
        assertEq(h.length(), 1);
        h.remove(A2);
        assertEq(h.length(), 0);
    }

    function test_remove_lazy_twoElements_removeLast() public {
        h.add(A1);
        h.add(A2);
        h.remove(A2);
        assertEq(h.length(), 1);
        h.remove(A1);
        assertEq(h.length(), 0);
    }

    function test_remove_lazy_threeElements_reverseOrder() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.remove(A3);
        assertEq(h.length(), 2);
        h.remove(A2);
        assertEq(h.length(), 1);
        h.remove(A1);
        assertEq(h.length(), 0);
    }

    function test_remove_lazy_threeElements_forwardOrder() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.remove(A1);
        assertEq(h.length(), 2);
        h.remove(A2);
        assertEq(h.length(), 1);
        h.remove(A3);
        assertEq(h.length(), 0);
    }

    function test_remove_eager_swapAndPop() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        assertTrue(h.remove(A2));
        assertEq(h.length(), 3);
        assertFalse(h.contains(A2));
        assertTrue(h.contains(A1));
        assertTrue(h.contains(A3));
        assertTrue(h.contains(A4));
        // A4 swapped into index 1.
        WOTSPlus.WinternitzAddress memory r1 = h.at(1);
        assertEq(r1.publicSeed, A4.publicSeed);
        assertEq(r1.publicKeyHash, A4.publicKeyHash);
    }

    function test_remove_eager_first() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        assertTrue(h.remove(A1));
        assertEq(h.length(), 3);
        assertFalse(h.contains(A1));
        // A4 swapped into index 0.
        WOTSPlus.WinternitzAddress memory r0 = h.at(0);
        assertEq(r0.publicSeed, A4.publicSeed);
        assertEq(r0.publicKeyHash, A4.publicKeyHash);
    }

    function test_remove_eager_last() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        assertTrue(h.remove(A4));
        assertEq(h.length(), 3);
        assertFalse(h.contains(A4));
    }

    function test_remove_eager_reverseOrder() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.remove(A4);
        h.remove(A3);
        h.remove(A2);
        h.remove(A1);
        assertEq(h.length(), 0);
    }

    function test_remove_eager_forwardOrder() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.remove(A1);
        h.remove(A2);
        h.remove(A3);
        h.remove(A4);
        assertEq(h.length(), 0);
    }

    function test_remove_eager_thenAddAgain() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.remove(A2);
        assertTrue(h.add(A2));
        assertEq(h.length(), 4);
        assertTrue(h.contains(A2));
    }

    function test_remove_allFromEager_thenReAdd() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.remove(A1);
        h.remove(A2);
        h.remove(A3);
        h.remove(A4);
        assertEq(h.length(), 0);
        // Set stays in eager mode (lazyLength != 0). Verify it still works.
        assertTrue(h.add(A5));
        assertEq(h.length(), 1);
        assertTrue(h.contains(A5));
        WOTSPlus.WinternitzAddress memory r0 = h.at(0);
        assertEq(r0.publicSeed, A5.publicSeed);
        assertEq(r0.publicKeyHash, A5.publicKeyHash);
    }

    function test_remove_eager_swapPreservesBothSlots() public {
        // Use distinctive values to detect cross-slot corruption.
        WOTSPlus.WinternitzAddress memory aA =
            WOTSPlus.WinternitzAddress(bytes32(uint256(0xAAAA)), bytes32(uint256(0xBBBB)));
        WOTSPlus.WinternitzAddress memory aB =
            WOTSPlus.WinternitzAddress(bytes32(uint256(0xCCCC)), bytes32(uint256(0xDDDD)));
        WOTSPlus.WinternitzAddress memory aC =
            WOTSPlus.WinternitzAddress(bytes32(uint256(0xEEEE)), bytes32(uint256(0xFFFF)));
        WOTSPlus.WinternitzAddress memory aD =
            WOTSPlus.WinternitzAddress(bytes32(uint256(0x1111)), bytes32(uint256(0x2222)));

        h.add(aA);
        h.add(aB);
        h.add(aC);
        h.add(aD);

        // Remove aA — aD should be swapped to index 0.
        h.remove(aA);
        WOTSPlus.WinternitzAddress memory r0 = h.at(0);
        assertEq(r0.publicSeed, aD.publicSeed, "seed not swapped correctly");
        assertEq(r0.publicKeyHash, aD.publicKeyHash, "hash not swapped correctly");
        // aB and aC remain in place.
        WOTSPlus.WinternitzAddress memory r1 = h.at(1);
        assertEq(r1.publicSeed, aB.publicSeed);
        assertEq(r1.publicKeyHash, aB.publicKeyHash);
        WOTSPlus.WinternitzAddress memory r2 = h.at(2);
        assertEq(r2.publicSeed, aC.publicSeed);
        assertEq(r2.publicKeyHash, aC.publicKeyHash);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           AT                                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_at_lazy() public {
        h.add(A1);
        h.add(A2);
        WOTSPlus.WinternitzAddress memory r0 = h.at(0);
        assertEq(r0.publicSeed, A1.publicSeed);
        assertEq(r0.publicKeyHash, A1.publicKeyHash);
        WOTSPlus.WinternitzAddress memory r1 = h.at(1);
        assertEq(r1.publicSeed, A2.publicSeed);
        assertEq(r1.publicKeyHash, A2.publicKeyHash);
    }

    function test_at_eager() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        WOTSPlus.WinternitzAddress memory r3 = h.at(3);
        assertEq(r3.publicSeed, A4.publicSeed);
        assertEq(r3.publicKeyHash, A4.publicKeyHash);
    }

    function test_at_revertsWhen_outOfBounds_empty() public {
        vm.expectRevert(EnumerableWinternitzAddressSet.IndexOutOfBounds.selector);
        h.at(0);
    }

    function test_at_revertsWhen_outOfBounds_lazy() public {
        h.add(A1);
        vm.expectRevert(EnumerableWinternitzAddressSet.IndexOutOfBounds.selector);
        h.at(1);
    }

    function test_at_revertsWhen_outOfBounds_eager() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        vm.expectRevert(EnumerableWinternitzAddressSet.IndexOutOfBounds.selector);
        h.at(4);
    }

    function test_at_revertsWhen_outOfBounds_large() public {
        h.add(A1);
        vm.expectRevert(EnumerableWinternitzAddressSet.IndexOutOfBounds.selector);
        h.at(type(uint256).max);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         VALUES                                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_values_empty() public view {
        WOTSPlus.WinternitzAddress[] memory vals = h.values();
        assertEq(vals.length, 0);
    }

    function test_values_lazy() public {
        h.add(A1);
        h.add(A2);
        WOTSPlus.WinternitzAddress[] memory vals = h.values();
        assertEq(vals.length, 2);
        assertEq(vals[0].publicSeed, A1.publicSeed);
        assertEq(vals[0].publicKeyHash, A1.publicKeyHash);
        assertEq(vals[1].publicSeed, A2.publicSeed);
        assertEq(vals[1].publicKeyHash, A2.publicKeyHash);
    }

    function test_values_eager() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.add(A5);
        WOTSPlus.WinternitzAddress[] memory vals = h.values();
        assertEq(vals.length, 5);
        assertEq(vals[0].publicSeed, A1.publicSeed);
        assertEq(vals[0].publicKeyHash, A1.publicKeyHash);
        assertEq(vals[4].publicSeed, A5.publicSeed);
        assertEq(vals[4].publicKeyHash, A5.publicKeyHash);
    }

    function test_values_matchesAt() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.add(A5);
        WOTSPlus.WinternitzAddress[] memory vals = h.values();
        for (uint256 i; i < vals.length; ++i) {
            WOTSPlus.WinternitzAddress memory r = h.at(i);
            assertEq(r.publicSeed, vals[i].publicSeed);
            assertEq(r.publicKeyHash, vals[i].publicKeyHash);
        }
    }

    function test_values_afterRemoval() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.remove(A2);
        WOTSPlus.WinternitzAddress[] memory vals = h.values();
        assertEq(vals.length, 3);
        // Index 0 = A1, Index 1 = A4 (swapped), Index 2 = A3.
        assertEq(vals[0].publicSeed, A1.publicSeed);
        assertEq(vals[0].publicKeyHash, A1.publicKeyHash);
        assertEq(vals[1].publicSeed, A4.publicSeed);
        assertEq(vals[1].publicKeyHash, A4.publicKeyHash);
        assertEq(vals[2].publicSeed, A3.publicSeed);
        assertEq(vals[2].publicKeyHash, A3.publicKeyHash);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          CLEAR                                 */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_clear_empty() public {
        assertEq(h.clear(), 0);
        assertEq(h.length(), 0);
    }

    function test_clear_lazyOne() public {
        h.add(A1);
        assertEq(h.clear(), 1);
        assertEq(h.length(), 0);
        assertFalse(h.contains(A1));
    }

    function test_clear_lazyTwo() public {
        h.add(A1);
        h.add(A2);
        assertEq(h.clear(), 2);
        assertEq(h.length(), 0);
        assertFalse(h.contains(A1));
        assertFalse(h.contains(A2));
    }

    function test_clear_lazyFull() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        assertEq(h.clear(), 3);
        assertEq(h.length(), 0);
        assertFalse(h.contains(A1));
        assertFalse(h.contains(A2));
        assertFalse(h.contains(A3));
    }

    function test_clear_eagerSmall() public {
        // 4 elements forces transition to eager phase.
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        assertEq(h.clear(), 4);
        assertEq(h.length(), 0);
        assertFalse(h.contains(A1));
        assertFalse(h.contains(A2));
        assertFalse(h.contains(A3));
        assertFalse(h.contains(A4));
    }

    function test_clear_eagerFull() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.add(A5);
        assertEq(h.clear(), 5);
        assertEq(h.length(), 0);
    }

    // Clear must wipe the position-mapping slots (eager phase) so that a
    // subsequent re-add of the same address starts clean — without this the
    // position mapping would still point into stale element slots.
    function test_clear_eager_thenReuse() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.clear();

        // Re-add the same addresses; they must be `add() == true` (i.e., not
        // already present) and queryable.
        assertTrue(h.add(A1));
        assertTrue(h.add(A2));
        assertEq(h.length(), 2);
        assertTrue(h.contains(A1));
        assertTrue(h.contains(A2));
        assertFalse(h.contains(A3));
        assertFalse(h.contains(A4));
    }

    // Eager phase must reset back to lazy on clear, so the first re-add
    // after clear should land in lazy slots and the length() helper must
    // reflect the correct count via the lazy-phase scan.
    function test_clear_eager_resetsToLazyPhase() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.clear();
        h.add(A1);
        assertEq(h.length(), 1);
        assertTrue(h.contains(A1));
    }

    // After eager-phase removals leave a hole in the array, clear must still
    // wipe every slot the library considers populated (length() before clear).
    function test_clear_eagerAfterRemoval() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);
        h.add(A5);
        h.remove(A2); // length now 4, A5 swapped into A2's index
        assertEq(h.clear(), 4);
        assertEq(h.length(), 0);
        assertFalse(h.contains(A1));
        assertFalse(h.contains(A3));
        assertFalse(h.contains(A4));
        assertFalse(h.contains(A5));
    }

    // Clear on one set must not touch a sibling set sharing the same parent
    // contract — i.e., it correctly scopes to the rootSlot derived from the
    // set's storage slot.
    function test_clear_doesNotAffectOtherSet() public {
        h.add(A1);
        h.add(A2);
        h.add2(A3);
        h.add2(A4);

        assertEq(h.clear(), 2);

        assertEq(h.length(), 0);
        assertEq(h.length2(), 2);
        assertTrue(h.contains2(A3));
        assertTrue(h.contains2(A4));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       FUZZ: CLEAR                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Force lazy phase: 1..3 distinct elements added, then clear.
    ///      Cleared count must equal prior length; post-clear length must be
    ///      zero; every added address must no longer be contained. Distinct
    ///      seeds are guaranteed via the loop index so dedup never silently
    ///      shrinks the populated size below `bound(...)`.
    function test_fuzz_clear_lazyPhase(uint256 n) public {
        LibPRNG.PRNG memory prng;
        prng.state = n;
        uint256 size = bound(prng.next(), 1, 3);

        bytes32[] memory hashes = new bytes32[](size);
        for (uint256 i; i < size; ++i) {
            // Distinct seed per iteration → no add() collisions.
            hashes[i] = bytes32(prng.next() | 1); // non-zero hash
            h.add(WOTSPlus.WinternitzAddress(bytes32(uint256(i) + 1), hashes[i]));
        }
        assertEq(h.length(), size, "all distinct adds landed (lazy)");

        uint256 cleared = h.clear();
        assertEq(cleared, size, "cleared count vs prior length");
        assertEq(h.length(), 0, "length after clear");

        for (uint256 i; i < size; ++i) {
            assertFalse(
                h.contains(WOTSPlus.WinternitzAddress(bytes32(uint256(i) + 1), hashes[i])),
                "stale residue after lazy-phase clear"
            );
        }
    }

    /// @dev Force eager phase: 4..16 distinct elements, then clear. Same
    ///      invariants as the lazy-phase fuzzer — but this path also
    ///      exercises the position-mapping wipe inside `clear`'s eager
    ///      branch, which is the bit a regression would silently break.
    function test_fuzz_clear_eagerPhase(uint256 n) public {
        LibPRNG.PRNG memory prng;
        prng.state = n;
        uint256 size = bound(prng.next(), 4, 16);

        bytes32[] memory hashes = new bytes32[](size);
        for (uint256 i; i < size; ++i) {
            hashes[i] = bytes32(prng.next() | 1);
            h.add(WOTSPlus.WinternitzAddress(bytes32(uint256(i) + 1), hashes[i]));
        }
        assertEq(h.length(), size, "all distinct adds landed (eager)");

        uint256 cleared = h.clear();
        assertEq(cleared, size, "cleared count vs prior length");
        assertEq(h.length(), 0, "length after clear");

        for (uint256 i; i < size; ++i) {
            assertFalse(
                h.contains(WOTSPlus.WinternitzAddress(bytes32(uint256(i) + 1), hashes[i])),
                "stale residue after eager-phase clear"
            );
        }
    }

    /// @dev Random churn (adds + removes against a reference model), but
    ///      seeded with a guaranteed initial add so every iteration starts
    ///      from a non-empty state. The reference array tracks the live set,
    ///      and we assert clear's returned count matches the reference's
    ///      final size — so we know clear was actually invoked on a
    ///      meaningful state, not silently on an empty set.
    function test_fuzz_clear_afterRandomChurn(uint256 n) public {
        unchecked {
            LibPRNG.PRNG memory prng;
            prng.state = n;
            uint256[] memory ref = _makePackedArray(0);
            uint256 mask = prng.next() % 2 == 0 ? 7 : 15;

            // Guarantee non-empty starting state so clear is never trivial.
            // Distinct seed (0xfeed...) avoids collision with the churn loop's
            // small-mask address space.
            {
                uint256 seedAnchor = uint256(0xfeed01);
                uint256 hashAnchor = uint256(0xfeed02);
                h.add(WOTSPlus.WinternitzAddress(bytes32(seedAnchor), bytes32(hashAnchor)));
                _addToPacked(ref, (seedAnchor << 128) | hashAnchor);
            }

            uint256 iters;
            do {
                uint256 seed = (prng.next() & mask) + 1;
                uint256 hash_ = (prng.next() & mask) + 1;
                uint256 packed = (seed << 128) | hash_;
                WOTSPlus.WinternitzAddress memory addr = WOTSPlus.WinternitzAddress(bytes32(seed), bytes32(hash_));

                if (prng.next() % 2 == 0) {
                    h.add(addr);
                    _addToPacked(ref, packed);
                } else {
                    h.remove(addr);
                    _removeFromPacked(ref, packed);
                }

                ++iters;
                if (iters == 256) break;
            } while (prng.next() % 8 != 0);

            uint256 priorLen = h.length();
            assertEq(priorLen, ref.length, "length pre-clear");
            assertGt(priorLen, 0, "anchor add must persist or churn must net-positive");

            uint256 cleared = h.clear();
            assertEq(cleared, priorLen, "cleared count vs prior length");
            assertEq(h.length(), 0, "length after clear");

            for (uint256 i; i < ref.length; ++i) {
                uint256 p = ref[i];
                assertFalse(
                    h.contains(WOTSPlus.WinternitzAddress(bytes32(p >> 128), bytes32(p & type(uint128).max))),
                    "stale residue after clear"
                );
            }
        }
    }

    /// @dev Random adds, clear, then a second random batch — both batches
    ///      bounded to be non-empty and distinct-seeded. The post-clear adds
    ///      must each return `true` (set is truly empty), length must match
    ///      the second batch size, and contains must report only the second
    ///      batch — proving the position-mapping wipe was total. If clear
    ///      ever forgets to zero an eager-phase position-mapping slot, this
    ///      test catches it the moment the second batch happens to pick a
    ///      seed that hash-collides with a first-batch entry.
    function test_fuzz_clear_thenReuse(uint256 n) public {
        LibPRNG.PRNG memory prng;
        prng.state = n;
        uint256 firstSize = bound(prng.next(), 1, 12);
        uint256 secondSize = bound(prng.next(), 1, 12);

        // First batch — distinct seeds in range [1, firstSize].
        for (uint256 i; i < firstSize; ++i) {
            h.add(WOTSPlus.WinternitzAddress(bytes32(uint256(i) + 1), bytes32(prng.next() | 1)));
        }
        assertEq(h.length(), firstSize, "first batch landed");
        h.clear();
        assertEq(h.length(), 0, "clear emptied set");

        // Second batch — overlapping seed range [1, secondSize] so any
        // surviving position-mapping entries from the first batch would be
        // hit. Hashes are independently random.
        bytes32[] memory secondHashes = new bytes32[](secondSize);
        for (uint256 i; i < secondSize; ++i) {
            secondHashes[i] = bytes32(prng.next() | 1);
            bool added = h.add(WOTSPlus.WinternitzAddress(bytes32(uint256(i) + 1), secondHashes[i]));
            assertTrue(added, "post-clear add must succeed (no stale residue)");
        }

        assertEq(h.length(), secondSize, "length after reuse");
        for (uint256 i; i < secondSize; ++i) {
            assertTrue(
                h.contains(WOTSPlus.WinternitzAddress(bytes32(uint256(i) + 1), secondHashes[i])),
                "missing post-clear addition"
            );
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      FUZZ: HEAVY                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function test_fuzz_addContainsRemove(bytes32 seed, bytes32 hash_) public {
        vm.assume(seed != bytes32(0) && hash_ != bytes32(0));
        WOTSPlus.WinternitzAddress memory addr = WOTSPlus.WinternitzAddress(seed, hash_);
        assertTrue(h.add(addr));
        assertTrue(h.contains(addr));
        assertEq(h.length(), 1);
        WOTSPlus.WinternitzAddress memory r = h.at(0);
        assertEq(r.publicSeed, seed);
        assertEq(r.publicKeyHash, hash_);
        assertTrue(h.remove(addr));
        assertFalse(h.contains(addr));
        assertEq(h.length(), 0);
    }

    /// @dev Heavy fuzz: random adds then random removes, verified against sorted reference.
    function test_fuzz_addRemoveSequence(uint256 n) public {
        unchecked {
            LibPRNG.PRNG memory prng;
            prng.state = n;
            uint256 mask = prng.next() % 2 == 0 ? 7 : 15;

            // --- Additions ---
            uint256[] memory additions = new uint256[](prng.next() % 16);
            for (uint256 i; i != additions.length; ++i) {
                uint256 seed = (prng.next() & mask) + 1; // 1..(mask+1), avoids zero
                uint256 hash_ = (prng.next() & mask) + 1;
                uint256 packed = (seed << 128) | hash_;
                additions[i] = packed;
                h.add(WOTSPlus.WinternitzAddress(bytes32(seed), bytes32(hash_)));
                assertTrue(h.contains(WOTSPlus.WinternitzAddress(bytes32(seed), bytes32(hash_))));
            }
            additions.sort();
            additions.uniquifySorted();
            assertEq(h.length(), additions.length, "length after adds");

            // Cross-check values() against sorted reference.
            {
                uint256[] memory packed = _packValues(h.values());
                packed.sort();
                assertEq(packed, additions, "values mismatch after adds");
            }

            // --- Removals ---
            uint256[] memory removals = new uint256[](prng.next() % 16);
            for (uint256 i; i != removals.length; ++i) {
                uint256 seed = (prng.next() & mask) + 1;
                uint256 hash_ = (prng.next() & mask) + 1;
                uint256 packed = (seed << 128) | hash_;
                removals[i] = packed;
                h.remove(WOTSPlus.WinternitzAddress(bytes32(seed), bytes32(hash_)));
                assertFalse(h.contains(WOTSPlus.WinternitzAddress(bytes32(seed), bytes32(hash_))));
            }
            removals.sort();
            removals.uniquifySorted();

            {
                uint256[] memory expected = additions.difference(removals);
                assertEq(h.length(), expected.length, "length after removals");
                uint256[] memory packed = _packValues(h.values());
                packed.sort();
                assertEq(packed, expected, "values mismatch after removals");
            }

            // Cross-check values/at consistency.
            _assertValuesMatchAt();
        }
    }

    /// @dev Open-ended fuzz: random interleaved adds/removes against a dynamic reference model.
    function test_fuzz_openEndedAddRemove(uint256 n) public {
        unchecked {
            LibPRNG.PRNG memory prng;
            prng.state = n;
            uint256[] memory ref = _makePackedArray(0);
            uint256 mask = prng.next() % 2 == 0 ? 7 : 15;
            uint256 iters;

            do {
                uint256 seed = (prng.next() & mask) + 1;
                uint256 hash_ = (prng.next() & mask) + 1;
                uint256 packed = (seed << 128) | hash_;
                WOTSPlus.WinternitzAddress memory addr = WOTSPlus.WinternitzAddress(bytes32(seed), bytes32(hash_));

                if (prng.next() % 2 == 0) {
                    h.add(addr);
                    _addToPacked(ref, packed);
                    assertTrue(h.contains(addr));
                } else {
                    h.remove(addr);
                    _removeFromPacked(ref, packed);
                    assertFalse(h.contains(addr));
                }

                assertEq(h.length(), ref.length, "length mismatch");

                // Periodic cross-checks.
                if (prng.next() % 8 == 0) {
                    _checkSortedEq(_packValues(h.values()), ref);
                    _assertValuesMatchAt();
                }

                ++iters;
                if (iters == 512) break;
            } while (prng.next() % 8 != 0);

            // Final cross-check.
            _checkSortedEq(_packValues(h.values()), ref);

            // Verify contains for all reference elements.
            for (uint256 i; i < ref.length; ++i) {
                uint256 p = ref[i];
                assertTrue(h.contains(WOTSPlus.WinternitzAddress(bytes32(p >> 128), bytes32(p & type(uint128).max))));
            }
        }
    }

    /// @dev Stress test: 10 elements (matching MAX_KEYS use case) with churn.
    function test_tenElements_addRemoveChurn() public {
        // Add 10 elements.
        for (uint256 i = 1; i <= 10; ++i) {
            assertTrue(h.add(WOTSPlus.WinternitzAddress(bytes32(i), bytes32(i + 100))));
        }
        assertEq(h.length(), 10);

        // Verify all present.
        for (uint256 i = 1; i <= 10; ++i) {
            assertTrue(h.contains(WOTSPlus.WinternitzAddress(bytes32(i), bytes32(i + 100))));
        }

        // Remove odd-indexed elements (1, 3, 5, 7, 9).
        for (uint256 i = 1; i <= 10; i += 2) {
            assertTrue(h.remove(WOTSPlus.WinternitzAddress(bytes32(i), bytes32(i + 100))));
        }
        assertEq(h.length(), 5);

        // Verify only evens remain.
        for (uint256 i = 1; i <= 10; ++i) {
            WOTSPlus.WinternitzAddress memory addr = WOTSPlus.WinternitzAddress(bytes32(i), bytes32(i + 100));
            if (i % 2 == 0) {
                assertTrue(h.contains(addr));
            } else {
                assertFalse(h.contains(addr));
            }
        }

        // Re-add removed elements.
        for (uint256 i = 1; i <= 10; i += 2) {
            assertTrue(h.add(WOTSPlus.WinternitzAddress(bytes32(i), bytes32(i + 100))));
        }
        assertEq(h.length(), 10);

        // Values/at cross-check.
        WOTSPlus.WinternitzAddress[] memory vals = h.values();
        assertEq(vals.length, 10);
        for (uint256 i; i < 10; ++i) {
            WOTSPlus.WinternitzAddress memory r = h.at(i);
            assertEq(r.publicSeed, vals[i].publicSeed);
            assertEq(r.publicKeyHash, vals[i].publicKeyHash);
            assertTrue(h.contains(vals[i]));
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     FUZZ: HELPERS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function _packValues(WOTSPlus.WinternitzAddress[] memory vals) internal pure returns (uint256[] memory packed) {
        packed = new uint256[](vals.length);
        for (uint256 i; i < vals.length; ++i) {
            packed[i] = (uint256(vals[i].publicSeed) << 128) | uint256(vals[i].publicKeyHash);
        }
    }

    /// @dev Allocate a reference array with capacity for up to 512 packed elements.
    function _makePackedArray(uint256 size) internal pure returns (uint256[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            mstore(result, size)
            mstore(0x40, add(result, shl(5, add(512, 1))))
        }
    }

    /// @dev Add `x` to packed reference array if not already present.
    function _addToPacked(uint256[] memory a, uint256 x) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            let exists := 0
            let n := mload(a)
            for {
                let i := 0
            } lt(i, n) {
                i := add(i, 1)
            } {
                if eq(mload(add(add(a, 0x20), shl(5, i))), x) {
                    exists := 1
                    break
                }
            }
            if iszero(exists) {
                n := add(n, 1)
                mstore(add(a, shl(5, n)), x)
                mstore(a, n)
            }
        }
    }

    /// @dev Remove `x` from packed reference array via swap-and-pop.
    function _removeFromPacked(uint256[] memory a, uint256 x) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            let n := mload(a)
            for {
                let i := 0
            } lt(i, n) {
                i := add(i, 1)
            } {
                let o := add(add(a, 0x20), shl(5, i))
                if eq(mload(o), x) {
                    mstore(o, mload(add(a, shl(5, n))))
                    mstore(a, sub(n, 1))
                    break
                }
            }
        }
    }

    /// @dev Sort both arrays and assert equality.
    function _checkSortedEq(uint256[] memory a, uint256[] memory b) internal pure {
        // Clone `b` to avoid mutating the reference.
        uint256[] memory bCopy = new uint256[](b.length);
        for (uint256 i; i < b.length; ++i) {
            bCopy[i] = b[i];
        }
        a.sort();
        bCopy.sort();
        assertEq(a, bCopy);
    }

    function _assertValuesMatchAt() internal view {
        WOTSPlus.WinternitzAddress[] memory vals = h.values();
        for (uint256 i; i < vals.length; ++i) {
            WOTSPlus.WinternitzAddress memory r = h.at(i);
            assertEq(r.publicSeed, vals[i].publicSeed, "values/at seed mismatch");
            assertEq(r.publicKeyHash, vals[i].publicKeyHash, "values/at hash mismatch");
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    DATA INTEGRITY                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Verify that removing an element clears the publicKeyHash slot (no ghost data).
    function test_remove_clearsPublicKeyHashSlot() public {
        h.add(A1);
        h.add(A2);
        h.add(A3);
        h.add(A4);

        // Remove all elements.
        h.remove(A1);
        h.remove(A2);
        h.remove(A3);
        h.remove(A4);

        // Add a fresh element. It goes to index 0.
        h.add(A5);
        WOTSPlus.WinternitzAddress memory r = h.at(0);
        assertEq(r.publicSeed, A5.publicSeed, "seed should be A5");
        assertEq(r.publicKeyHash, A5.publicKeyHash, "hash should be A5, not ghost data");
        assertEq(h.length(), 1);

        // Only A5 should exist.
        assertFalse(h.contains(A1));
        assertFalse(h.contains(A2));
        assertFalse(h.contains(A3));
        assertFalse(h.contains(A4));
    }
}
