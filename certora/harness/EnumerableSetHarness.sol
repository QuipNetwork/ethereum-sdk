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

import { EnumerableSetLib } from "solady-0.1.26/src/utils/EnumerableSetLib.sol";

/// @title EnumerableSetHarness
/// @notice Rerouting-summary harness for Solady `EnumerableSetLib.Bytes32Set`.
/// @dev Why: the Prover's skey annotation does not convert the operand of
///      `BWNot`, so inlining Solady's set code (`not(_rootSlot(...))` for the
///      lazy count) yields `BWNot(<skey>)` and the local prover dies with
///      INTERNAL_TAC_TYPE_CHECKER (code 1714349382) before any SMT query. The
///      spec reroutes `length`, `contains`, `indexOf`, `add`, `remove` and
///      `values` here; `at` cannot be rerouted (`at` is a CVL keyword, so the
///      methods block cannot name it) but its own body contains no `not()` —
///      once `length` is rerouted, the inlined `at` is crash-free.
///
///      To keep the inlined `at` consistent with the rerouted writers, the
///      ELEMENT layout MIRRORS Solady byte-for-byte:
///        root        = keccak256(p . 0x18fb5864)   (Solady `_rootSlot`)
///        element[i]  = root + i                     (insertion order)
///      The count and the index map are harness-private (every Solady reader
///      of them is rerouted here), so they live at 64-byte keccak bases off
///      `p` instead of Solady's layout:
///        count  = keccak256(abi.encode(p, 1))
///        index  = keccak256(abi.encodePacked(value, keccak256(abi.encode(p, 2))))
///                 -> index + 1 (0 = absent)
///      The 64-byte shape is deliberate: the Prover's quantifier compiler can
///      only summarize 32/64-byte hashes (RawHashToSimpleHashConverter), while
///      the 36-byte `_rootSlot` hash is structurally unrepresentable there —
///      so quantified invariants may read `getVettedCodeIndex` but never the
///      element region.
///
///      Semantics mirror Solady: append-at-end `add` (false if present),
///      swap-with-last `remove` (false if absent), `indexOf` = `NOT_FOUND`
///      when absent, out-of-map removals report absent (Solady would scan the
///      inline elements), and `_ZERO_SENTINEL` inputs to `add`/`remove` revert
///      with `ValueIsZeroSentinel()`. Deviation: `bytes32(0)` is stored raw
///      instead of as the sentinel — observable reads (`at`, `values`) map both
///      to `bytes32(0)` anyway.
library EnumerableSetHarness {
    error ValueIsZeroSentinel();

    uint256 internal constant NOT_FOUND = type(uint256).max;

    /// @dev Solady `_ZERO_SENTINEL`; `add`/`remove` of this value reverts.
    bytes32 private constant _ZERO_SENTINEL = bytes32(uint256(0xfbb67fda52d4bfb8bf));

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    EXTERNAL                            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function length(
        EnumerableSetLib.Bytes32Set storage set
    ) external view returns (uint256 result) {
        result = _read(_slotCount(set));
    }

    function contains(
        EnumerableSetLib.Bytes32Set storage set,
        bytes32 value
    ) external view returns (bool result) {
        result = _read(_slotIndex(set, value)) != 0;
    }

    function indexOf(
        EnumerableSetLib.Bytes32Set storage set,
        bytes32 value
    ) external view returns (uint256 result) {
        uint256 packed = _read(_slotIndex(set, value));
        result = packed == 0 ? NOT_FOUND : packed - 1;
    }

    function add(
        EnumerableSetLib.Bytes32Set storage set,
        bytes32 value
    ) external returns (bool result) {
        if (value == _ZERO_SENTINEL) revert ValueIsZeroSentinel();
        if (_read(_slotIndex(set, value)) != 0) return false;
        uint256 len = _read(_slotCount(set));
        unchecked {
            _write(_slotElem(set, len), uint256(value));
        }
        _write(_slotIndex(set, value), len + 1);
        _write(_slotCount(set), len + 1);
        result = true;
    }

    function remove(
        EnumerableSetLib.Bytes32Set storage set,
        bytes32 value
    ) external returns (bool result) {
        if (value == _ZERO_SENTINEL) revert ValueIsZeroSentinel();
        uint256 packed = _read(_slotIndex(set, value));
        if (packed == 0) return false;
        uint256 idx = packed - 1;
        uint256 len = _read(_slotCount(set));
        if (idx >= len) return false;
        uint256 lastIdx = len - 1;
        if (idx != lastIdx) {
            bytes32 lastValue;
            unchecked {
                lastValue = bytes32(_read(_slotElem(set, lastIdx)));
                _write(_slotElem(set, idx), uint256(lastValue));
            }
            _write(_slotIndex(set, lastValue), idx + 1);
        }
        unchecked {
            _write(_slotElem(set, lastIdx), uint256(bytes32(0)));
        }
        _write(_slotIndex(set, value), 0);
        _write(_slotCount(set), lastIdx);
        result = true;
    }

    function values(
        EnumerableSetLib.Bytes32Set storage set
    ) external view returns (bytes32[] memory result) {
        uint256 len = _read(_slotCount(set));
        result = new bytes32[](len);
        for (uint256 i; i < len; ++i) {
            unchecked {
                result[i] = bytes32(_read(_slotElem(set, i)));
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    INTERNALS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Solady `_rootSlot(Bytes32Set)`: `keccak256(p . word-set-seed)`.
    ///      Copied verbatim (no `not()`) so the inlined `at` and this harness
    ///      address the same element cells.
    function _root(
        EnumerableSetLib.Bytes32Set storage set
    ) private pure returns (bytes32 r) {
        /// @solidity memory-safe-assembly
        assembly ("memory-safe") {
            mstore(0x04, 0x18fb5864) // `_ENUMERABLE_WORD_SET_SLOT_SEED`
            mstore(0x00, set.slot)
            r := keccak256(0x00, 0x24)
        }
    }

    function _slotCount(
        EnumerableSetLib.Bytes32Set storage set
    ) private pure returns (bytes32) {
        return keccak256(abi.encode(_base(set), uint256(1)));
    }

    /// @dev Deliberately keyed off a 64-byte `keccak256(abi.encode(p, 2))`
    ///      base rather than Solady's 36-byte `_rootSlot`: only the element
    ///      cells (`root + i`) must stay Solady-compatible for the inlined
    ///      `at`; the index map is harness-private, and 64-byte hashes are the
    ///      shape the Prover's quantifier compiler can summarize (36-byte
    ///      memory hashes cannot — see RawHashToSimpleHashConverter, which
    ///      lifts only 32/64-byte hashes to AssignSimpleSha3Cmd).
    function _slotIndex(
        EnumerableSetLib.Bytes32Set storage set,
        bytes32 value
    ) private pure returns (bytes32) {
        return keccak256(abi.encodePacked(value, keccak256(abi.encode(_base(set), uint256(2)))));
    }

    function _slotElem(
        EnumerableSetLib.Bytes32Set storage set,
        uint256 i
    ) private pure returns (bytes32) {
        return bytes32(uint256(_root(set)) + i);
    }

    function _base(
        EnumerableSetLib.Bytes32Set storage set
    ) private pure returns (bytes32 p) {
        assembly ("memory-safe") {
            p := set.slot
        }
    }

    function _read(
        bytes32 slot
    ) private view returns (uint256 v) {
        assembly ("memory-safe") {
            v := sload(slot)
        }
    }

    function _write(
        bytes32 slot,
        uint256 v
    ) private {
        assembly ("memory-safe") {
            sstore(slot, v)
        }
    }
}
