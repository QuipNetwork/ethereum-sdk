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

library QuipPaymasterStorage {
    /// @custom:storage-location erc7201:quip.storage.paymaster
    struct Layout {
        /// @dev Per-wallet WOTS+ verifier keys for gas sponsorship authorization.
        mapping(address wallet => WOTSPlus.WinternitzAddress verifier) verifiers;
        /// @dev Monotonic global occupancy index keyed by
        ///      `EfficientHashLib.hash(seed, keyHash)`. Marks a verifier key as
        ///      ever-registered across the whole paymaster — once `true`, the
        ///      flag is never cleared.
        mapping(bytes32 keyHash => bool used) verifierKeyUsed;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("quip.storage.paymaster")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _PAYMASTER_STORAGE_SLOT =
        0x8926ce57d385a1d96a00d5ce1618d3e300ce201cbf2177f181835ec0ca228b00;

    /// @dev Returns the ERC-7201 namespaced storage layout.
    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := _PAYMASTER_STORAGE_SLOT
        }
    }
}
