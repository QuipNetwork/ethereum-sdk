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

import {CREATE3} from "solady-0.1.26/src/utils/CREATE3.sol";
import {IDeployer} from "./interfaces/IDeployer.sol";

/// @title Deployer
/// @notice Deploys contracts with consistent addresses across EVM chains using CREATE3.
contract Deployer is IDeployer {
    /// @inheritdoc IDeployer
    function deploy(
        bytes memory bytecode,
        bytes32 salt
    ) public returns (address) {
        address contractAddr = CREATE3.deployDeterministic(bytecode, salt);
        emit Deploy(contractAddr);
        return contractAddr;
    }

    /// @inheritdoc IDeployer
    function predictAddress(bytes32 salt) public view returns (address) {
        return CREATE3.predictDeterministicAddress(salt);
    }
}
