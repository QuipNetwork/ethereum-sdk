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
pragma solidity ^0.8.28;

contract DummyContract {
    uint256 public value;

    function setValue(uint256 _value) external payable {
        require(msg.value >= 0.01 ether, "Need at least 0.01 ETH");
        value = _value;
    }

    function setValueNoFee(uint256 _value) external {
        value = _value;
    }

    function failingFunction() external pure {
        require(false, "Function always fails");
    }
}
