// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {Test} from "forge-std-1.14.0/Test.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";
import {EnumerableWinternitzAddressSet} from "contracts/wots/EnumerableWinternitzAddressSet.sol";

/// @dev Reuses the same harness shape as the main suite, scoped tighter so
///      this file is self-contained.
contract _ValuesSentinelHarness {
    using EnumerableWinternitzAddressSet for EnumerableWinternitzAddressSet.WinternitzAddressSet;

    EnumerableWinternitzAddressSet.WinternitzAddressSet private s;

    function add(WOTSPlus.WinternitzAddress memory addr) external returns (bool) {
        return s.add(addr);
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
}

/// @title EnumerableWinternitzAddressSet.values() — struct-size sentinel
/// @dev Pins the memory layout assumption that `WOTSPlus.WinternitzAddress`
///      is exactly two `bytes32` fields (`_WINTERNITZ_ADDRESS_SIZE = 0x40`).
///      If a future change adds, reorders, or repacks a field, the
///      `values()` allocator math
///        `add(structs, mul(n, _WINTERNITZ_ADDRESS_SIZE))`
///      and the per-element offset
///        `mul(i, _WINTERNITZ_ADDRESS_SIZE)`
///      would produce a malformed array (overlapping structs, free-pointer
///      advanced past the wrong byte, garbage in the gap) — but Solidity
///      itself would still compile, and the canonical access pattern
///      `values()[i]` might still appear to work because indexing follows
///      the pointer slots written at `add(ptrs, shl(5, i))`.
///
///      Strategy: populate the set across lazy- and eager-phase sizes, then
///      assert that `keccak256(abi.encode(values()[i])) ==
///      keccak256(abi.encode(at(i)))` for every i. `at()` reads element
///      slots directly via `sload`, so any layout drift between the storage
///      shape and the in-memory struct shape produced by `values()` shows
///      up as a hash mismatch on the very next test run.
contract EnumerableWinternitzAddressSet_values_sentinel is Test {
    _ValuesSentinelHarness internal harness;

    function setUp() public {
        harness = new _ValuesSentinelHarness();
    }

    /*─────────────────────────── helpers ───────────────────────────────*/

    function _mkAddr(uint256 i) internal pure returns (WOTSPlus.WinternitzAddress memory) {
        return WOTSPlus.WinternitzAddress({
            publicSeed: keccak256(abi.encode("seed", i)), publicKeyHash: keccak256(abi.encode("hash", i))
        });
    }

    /// Populate the set with `n` distinct elements derived deterministically
    /// from `i`, then for every index assert that `values()[i]` is byte-
    /// identical to `at(i)`. `at(i)` is the canonical storage reader;
    /// `values()` is the assembly-allocated batch reader whose struct math
    /// depends on `_WINTERNITZ_ADDRESS_SIZE`.
    function _assertValuesMatchAt(uint256 n) internal {
        for (uint256 i = 0; i < n; ++i) {
            assertTrue(harness.add(_mkAddr(i)), "add must report new element");
        }
        assertEq(harness.length(), n, "length mirrors insertions");

        WOTSPlus.WinternitzAddress[] memory batch = harness.values();
        assertEq(batch.length, n, "values().length matches set size");

        for (uint256 i = 0; i < n; ++i) {
            WOTSPlus.WinternitzAddress memory canonical = harness.at(i);
            // Field-by-field equality.
            assertEq(batch[i].publicSeed, canonical.publicSeed, "publicSeed drift between values() and at()");
            assertEq(batch[i].publicKeyHash, canonical.publicKeyHash, "publicKeyHash drift between values() and at()");
            // Total-byte-shape equality. If the in-memory struct grew or
            // shrank silently, abi.encode would still pad/truncate per the
            // type's declared layout — so this is the layout sentinel.
            assertEq(
                keccak256(abi.encode(batch[i])),
                keccak256(abi.encode(canonical)),
                "struct-shape drift between values() and at()"
            );
        }
    }

    /*─────────────────────── lazy-phase coverage ───────────────────────*/

    function test_values_n0_returnsEmpty() public view {
        WOTSPlus.WinternitzAddress[] memory batch = harness.values();
        assertEq(batch.length, 0, "empty set returns empty array");
    }

    function test_values_n1_matchesAt() public {
        _assertValuesMatchAt(1);
    }

    function test_values_n2_matchesAt() public {
        _assertValuesMatchAt(2);
    }

    function test_values_n3_matchesAt() public {
        _assertValuesMatchAt(3);
    }

    /*─────────────────────── eager-phase coverage ──────────────────────*/

    /// Right at the lazy/eager phase boundary. The library transitions to
    /// the position-mapping layout when the 4th element is added — this
    /// exercises the freshly-built mapping path.
    function test_values_n4_matchesAt() public {
        _assertValuesMatchAt(4);
    }

    /// MAX_KEYS (10) is the production invariant size; this is the most
    /// load-bearing case for the on-chain wallet keysets.
    function test_values_n10_matchesAt() public {
        _assertValuesMatchAt(10);
    }

    /// Larger eager-phase size to exercise the offset math at scale.
    function test_values_n25_matchesAt() public {
        _assertValuesMatchAt(25);
    }

    /*─────────────────────── memory-isolation guard ────────────────────*/

    /// `values()` writes to fresh memory above the free-memory pointer and
    /// must advance the pointer past the last allocated struct. If the
    /// struct-size constant disagrees with the actual in-memory size, a
    /// follow-up allocation would overlap the last struct and the second
    /// `values()` call would either corrupt the first array's tail or
    /// expose the corruption as a hash mismatch.
    function test_values_callTwice_independentMemory() public {
        for (uint256 i = 0; i < 10; ++i) {
            harness.add(_mkAddr(i));
        }
        WOTSPlus.WinternitzAddress[] memory first = harness.values();
        WOTSPlus.WinternitzAddress[] memory second = harness.values();
        assertEq(first.length, second.length);
        for (uint256 i = 0; i < first.length; ++i) {
            assertEq(
                keccak256(abi.encode(first[i])),
                keccak256(abi.encode(second[i])),
                "second call corrupted first call's memory"
            );
        }
    }

    /*─────────────────────── struct-size pin ───────────────────────────*/

    /// Sentinel-of-the-sentinel: if `WOTSPlus.WinternitzAddress` ever
    /// changes shape, Solidity's `abi.encode` on a stack instance will
    /// produce a payload of a different size, and this guard will fire
    /// before any of the above tests do. Documents the load-bearing
    /// number alongside the library constant.
    function test_winternitzAddress_inMemorySizeIs64Bytes() public pure {
        WOTSPlus.WinternitzAddress memory a;
        // ABI encoding of a 2 × bytes32 struct is exactly 64 bytes — the
        // same as `_WINTERNITZ_ADDRESS_SIZE = 0x40` in the library.
        assertEq(abi.encode(a).length, 64);
    }
}
