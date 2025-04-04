// Copyright (C) 2024 quip.network
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

// Deployer allows us to deploy contracts with consistent addresses across EVM chains
// using create2
contract Deployer {
    event Deploy(address addr);

    function deploy(bytes memory bytecode, uint256 salt) public returns (address) {
        address contractAddr;
        assembly {
            // code starts after the first 32 bytes...
            // https://ethereum-blockchain-developer.com/110-upgrade-smart-contracts/12-metamorphosis-create2/
            let code := add(0x20, bytecode)
            let codeSize := mload(bytecode)
            contractAddr := create2(callvalue(), code, codeSize, salt)

            // revert on failure
            if iszero(extcodesize(contractAddr)) {
                revert(0, 0)
            }
        }      
        emit Deploy(contractAddr);
        return contractAddr;
    }
}