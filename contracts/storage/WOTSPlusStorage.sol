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
import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";

library WOTSPlusStorage {
    /// @custom:storage-location erc7201:quip.storage.wallet.wotsplus
    struct Layout {
        address payable quipFactory;
        WOTSPlus.WinternitzAddress pqOwner;
        EnumerableSetLib.Bytes32Set recoveryKeyHashes;
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
