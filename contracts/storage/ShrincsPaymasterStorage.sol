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
        /// @dev Per-wallet SHRINCS verifier-key bundle commitment for gas-sponsorship
        ///      authorization. A separate key from the wallet's own signing key; registered
        ///      by the paymaster owner via `setShrincsVerifier`.
        mapping(address wallet => bytes32 commitment) shrincsCommitment;
        /// @dev Per-wallet parameter set for the verifier key (stored as uint8).
        mapping(address wallet => uint8 parameterSetId) shrincsParameterSetId;
        /// @dev Per-wallet next expected stateful leaf index (MonotonicIndex anti-replay).
        ///      Advanced during `validatePaymasterUserOp`; fresh keys start at 1.
        mapping(address wallet => uint32 nextLeaf) nextStatefulLeafIndex;
        /// @dev Per-wallet verifier-key epoch, bumped whenever the owner rotates the
        ///      registered key. Bound into the canonical action context so signatures from a
        ///      prior verifier epoch cannot be replayed.
        mapping(address wallet => uint256 epoch) keyVersion;
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
