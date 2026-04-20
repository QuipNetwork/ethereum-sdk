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

import {EnumerableWinternitzAddressSet as Keyset} from "../libraries/EnumerableWinternitzAddressSet.sol";

library WOTSPlusStorage {
    /// @custom:storage-location erc7201:quip.storage.wallet.wotsplus
    struct Layout {
        /// @dev Set once during `initialize`; effectively immutable after deployment.
        address payable quipFactory;
        /// @dev Enumerable set of Winternitz public keys authorized to sign guarded
        ///      transactions. Each op names a (currentKey, nextKey) pair; on success the
        ///      current key is consumed and the next is installed, preserving WOTS+
        ///      one-time-use while permitting parallel outstanding signatures.
        Keyset.WinternitzAddressSet transactionKeys;
        /// @dev Enumerable set of Winternitz public keys authorized to recover the wallet or
        ///      authorize an emergency implementation upgrade. Consumed one-time on use.
        ///      Capacity: `MAX_KEYS`.
        Keyset.WinternitzAddressSet recoveryKeys;
        /// @dev Enumerable set of Winternitz public keys authorized to sign ERC-1271 messages.
        ///      Managed post-init via transaction-key-authenticated calls. Capacity: `MAX_KEYS`.
        Keyset.WinternitzAddressSet verificationKeys;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("quip.storage.wallet.wotsplus")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _WOTSPLUS_STORAGE_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;

    /// @dev Returns the ERC-7201 namespaced storage layout.
    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := _WOTSPLUS_STORAGE_SLOT
        }
    }
}
