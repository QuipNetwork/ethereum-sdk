// Copyright (C) 2026 quip.network
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

library ShrincsPaymasterStorage {
    /// @custom:storage-location erc7201:quip.storage.paymaster.shrincs
    struct Layout {
        /// @dev The single global SHRINCS verifier-key bundle commitment that authorizes gas
        ///      sponsorship. The paymaster operator (the sponsor) holds one stateful key and signs
        ///      every userOp it is willing to sponsor; the binding hash commits to `userOp.sender`,
        ///      so a signature minted for one wallet cannot be replayed against another. Zero means
        ///      the paymaster is unconfigured. Registered at `initialize`; the stateful subkey is
        ///      rotated by the owner via `rotateStatefulKey` (the stateless half never rotates).
        bytes32 shrincsCommitment;
        /// @dev Leaf budget cached from the registered key so the paymaster can reject signatures
        ///      past the budget and expose `remainingStatefulSignatures()`.
        uint32 maxSignatures;
        /// @dev Count of stateful leaves consumed in the current epoch. Backs
        ///      `remainingStatefulSignatures()`; reset to 0 on every `rotateStatefulKey`. NOT the
        ///      anti-replay mechanism — that is `usedStatefulLeafBitmap` below.
        uint32 statefulLeavesUsed;
        /// @dev Global verifier-key epoch. The initial key (set at `initialize`) is epoch 0; every
        ///      `rotateStatefulKey` rotation bumps it. Bound into the canonical action context and
        ///      used to namespace the leaf bitmap so a rotation starts from a fresh (all-unused)
        ///      namespace. MONOTONIC — only ever increments, so a rotated key can never reuse a
        ///      namespace that already has consumed leaves.
        uint256 keyVersion;
        /// @dev Stateful-leaf anti-replay, namespaced by `keyVersion`. A leaf is consumable once and
        ///      in ANY order (no sequential constraint), so out-of-order userOp landing never
        ///      reverts. `usedStatefulLeafBitmap[keyVersion][leafIndex >> 8]` bit `leafIndex & 0xff`
        ///      is set when leaf `leafIndex` is consumed.
        mapping(uint256 keyVersion => mapping(uint256 wordIndex => uint256 usedBits)) usedStatefulLeafBitmap;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("quip.storage.paymaster.shrincs")) - 1))
    ///      & ~bytes32(uint256(0xff))
    bytes32 private constant _SHRINCS_PAYMASTER_STORAGE_SLOT =
        0xf7105c87ba7715caaefb344b6f917b23c0076d42eb62a45375e3717cb7ad3900;

    /// @dev Returns the ERC-7201 namespaced storage layout.
    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := _SHRINCS_PAYMASTER_STORAGE_SLOT
        }
    }
}
