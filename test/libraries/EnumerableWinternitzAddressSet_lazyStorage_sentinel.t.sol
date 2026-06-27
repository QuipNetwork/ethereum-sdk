// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet} from "contracts/wots/EnumerableWinternitzAddressSet.sol";

/// @dev Harness exposing the set's `_rootSlot` derivation so the test can
///      `vm.load` specific slots. The derivation is replicated verbatim
///      from the library's private `_rootSlot` helper — if `_SLOT_SEED`
///      ever changes upstream, this harness drifts and the lazy-phase
///      slot-mapping tests fail loudly. That's a load-bearing regression
///      signal in its own right (storage-layout incompatibility across
///      versions), separate from the lazy-stride pin this file is about.
contract _LazyStorageSentinelHarness {
    using EnumerableWinternitzAddressSet for EnumerableWinternitzAddressSet.WinternitzAddressSet;

    // `s` must be the first state variable so `s.slot == 0`. The
    // `rootSlot()` view below assumes this layout; if anyone adds a state
    // variable before `s`, every slot-load in the test file shifts and
    // the suite fails at the very first lazy-phase assertion.
    EnumerableWinternitzAddressSet.WinternitzAddressSet private s;

    function add(WOTSPlus.WinternitzAddress memory addr) external returns (bool) {
        return s.add(addr);
    }

    function length() external view returns (uint256) {
        return s.length();
    }

    /// @dev Replicates the library's private `_rootSlot(set)` derivation.
    function rootSlot() external pure returns (bytes32 r) {
        bytes32 slot;
        /// @solidity memory-safe-assembly
        assembly {
            slot := s.slot
        }
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x04, 0x3e9f5d6a) // _SLOT_SEED
            mstore(0x00, slot)
            r := keccak256(0x00, 0x24)
        }
    }
}

/// @title EnumerableWinternitzAddressSet — lazy-phase storage stride sentinel
/// @dev Pins the lazy-phase storage layout that `length()`, `contains()`,
///      `add()`, `remove()`, and `clear()` all assume:
///        - **Element stride = 2 slots.** Element `i ∈ {0, 1, 2}` occupies
///          slots `rootSlot+2i` (publicSeed) and `rootSlot+2i+1` (publicKeyHash).
///        - **Lazy capacity = 3 elements.** The 4th `add()` transitions to
///          eager and writes a non-zero `lazyLength` sentinel at the slot
///          addressed by `not(rootSlot)`.
///        - **`lazyLength` encoding.** The slot stores `(count << 1) | 1`
///          once eager. Lazy phase ⇔ the slot reads zero.
///
///      Latent regression: the stride hardcodes (`+0/+1, +2/+3, +4/+5`) and
///      the lazy-capacity hardcode (3) live across multiple assembly blocks
///      inside the library — `length()` lines 103-120, `contains()` lines
///      144-156, `add()` lines 193-276, `remove()`, `clear()`. None of them
///      reference a shared constant: they're all literals. If
///      `WinternitzAddress` ever grew a third field (now 3 slots / element),
///      the library would compile, the lazy-phase `add()` paths would write
///      into the wrong slots, and `length()`/`contains()` would silently
///      return stale data.
///
///      Parallel coverage of the in-memory (NOT storage) struct size, used
///      by the eager-phase `values()` allocator, lives in
///      `EnumerableWinternitzAddressSet_values_sentinel.t.sol`. The two
///      files together pin both layout dimensions the library hardcodes.
contract EnumerableWinternitzAddressSet_lazyStorage_sentinel is Test {
    _LazyStorageSentinelHarness internal harness;

    function setUp() public {
        harness = new _LazyStorageSentinelHarness();
    }

    /*─────────────────────────── helpers ───────────────────────────────*/

    /// @dev Distinct non-zero seed/hash per index. `add()` reverts on
    ///      zero-valued fields, so deterministic non-zero values are
    ///      required to drive the lazy-phase paths.
    function _addr(uint256 i) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return WOTSPlus.WinternitzAddress({
            publicSeed: keccak256(abi.encode("lazy-seed", i)), publicKeyHash: keccak256(abi.encode("lazy-hash", i))
        });
    }

    /// @dev Read storage slot `rootSlot + offset` directly. The library's
    ///      lazy-phase assembly addresses elements via plain integer
    ///      addition on `rootSlot`; this helper mirrors that pattern.
    function _loadOffset(uint256 offset) internal view returns (bytes32) {
        return vm.load(address(harness), bytes32(uint256(harness.rootSlot()) + offset));
    }

    /// @dev Read the lazy-length sentinel slot at `not(rootSlot)` — i.e. the
    ///      bitwise complement of the root slot. The library uses this slot
    ///      as both the lazy/eager flag and (once eager) the encoded count.
    function _loadLazyLengthSlot() internal view returns (bytes32) {
        return vm.load(address(harness), ~harness.rootSlot());
    }

    /*────────────── per-element slot-position sentinels ────────────────*/

    /// @dev Element 0 must land at rootSlot+0 (publicSeed) and rootSlot+1
    ///      (publicKeyHash). Catches a stride change at index 0.
    function test_lazyPhase_element0_occupiesSlotsZeroAndOne() public {
        WOTSPlus.WinternitzAddress memory a = _addr(0);
        harness.add(a);
        assertEq(_loadOffset(0), a.publicSeed, "elem 0 publicSeed slot");
        assertEq(_loadOffset(1), a.publicKeyHash, "elem 0 publicKeyHash slot");
    }

    /// @dev Element 1 must land at rootSlot+2/+3. Catches a stride change
    ///      at index 1 (e.g. accidental +1 stride from copy-paste).
    function test_lazyPhase_element1_occupiesSlotsTwoAndThree() public {
        harness.add(_addr(0));
        WOTSPlus.WinternitzAddress memory a = _addr(1);
        harness.add(a);
        assertEq(_loadOffset(2), a.publicSeed, "elem 1 publicSeed slot");
        assertEq(_loadOffset(3), a.publicKeyHash, "elem 1 publicKeyHash slot");
    }

    /// @dev Element 2 must land at rootSlot+4/+5. Last lazy-phase slot
    ///      pair; the next add transitions to eager.
    function test_lazyPhase_element2_occupiesSlotsFourAndFive() public {
        harness.add(_addr(0));
        harness.add(_addr(1));
        WOTSPlus.WinternitzAddress memory a = _addr(2);
        harness.add(a);
        assertEq(_loadOffset(4), a.publicSeed, "elem 2 publicSeed slot");
        assertEq(_loadOffset(5), a.publicKeyHash, "elem 2 publicKeyHash slot");
    }

    /*──────────────── lazy-length sentinel transitions ──────────────────*/

    /// @dev While lazy (≤ 3 elements), the `not(rootSlot)` slot must read
    ///      zero. `length()` branches on this — non-zero ⇒ eager-phase
    ///      lookup path.
    function test_lazyPhase_lazyLengthSentinelIsZeroForOneToThreeElements() public {
        harness.add(_addr(0));
        assertEq(_loadLazyLengthSlot(), bytes32(0), "1 elem: still lazy");
        harness.add(_addr(1));
        assertEq(_loadLazyLengthSlot(), bytes32(0), "2 elems: still lazy");
        harness.add(_addr(2));
        assertEq(_loadLazyLengthSlot(), bytes32(0), "3 elems: still lazy");
    }

    /// @dev The 4th add triggers lazy→eager transition. The library writes
    ///      `or(1, shl(1, 4)) == 9` to the lazy-length slot: low bit is the
    ///      "eager" flag, upper bits encode count. If the encoding scheme
    ///      changes silently, every read-path that checks this slot drifts.
    function test_lazyPhase_transitionsToEagerOnFourthAdd() public {
        harness.add(_addr(0));
        harness.add(_addr(1));
        harness.add(_addr(2));
        assertEq(_loadLazyLengthSlot(), bytes32(0), "precondition: still lazy after 3 adds");
        harness.add(_addr(3));
        // 9 = (4 << 1) | 1 — see library line 274.
        assertEq(_loadLazyLengthSlot(), bytes32(uint256(9)), "4 elems: (count << 1) | eager-flag");
        // Element 3 must land at slots 6/7 — the next stride step.
        WOTSPlus.WinternitzAddress memory a3 = _addr(3);
        assertEq(_loadOffset(6), a3.publicSeed, "elem 3 publicSeed slot");
        assertEq(_loadOffset(7), a3.publicKeyHash, "elem 3 publicKeyHash slot");
    }

    /// @dev Eager-phase additions continue the encoding: a 5th element
    ///      makes the slot read `(5 << 1) | 1 == 11`. Pins the increment
    ///      arithmetic in the eager add-path against the lazy-phase
    ///      transition arithmetic.
    function test_eagerPhase_fifthAddIncrementsCountInLazyLengthSlot() public {
        for (uint256 i = 0; i < 5; ++i) {
            harness.add(_addr(i));
        }
        assertEq(_loadLazyLengthSlot(), bytes32(uint256(11)));
        assertEq(harness.length(), 5);
    }

    /*───────────────── stride-derivation cross-check ───────────────────*/

    /// @dev Sentinel-of-the-sentinel: the stride of 2 derives from
    ///      `WinternitzAddress` having exactly two 32-byte fields. If a
    ///      future struct change adds a field, this assertion fails BEFORE
    ///      the slot-position assertions above do — surfacing the root
    ///      cause directly rather than as a mysterious slot mismatch.
    function test_lazyStride_derivesFromTwoFieldStruct() public pure {
        WOTSPlus.WinternitzAddress memory a;
        // abi.encode produces 32 bytes per static field. Two slots ⇒ 64.
        assertEq(abi.encode(a).length, 64, "WinternitzAddress is 64 bytes");
        // Storage stride is `encodedSize / 32 = 2`. The library hardcodes
        // this as literal +2 increments throughout the lazy-phase asm.
        assertEq(uint256(64 / 32), uint256(2));
    }
}
