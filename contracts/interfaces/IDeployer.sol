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

/// @title IDeployer
/// @notice Deploys contracts with deterministic addresses across EVM chains using CREATE3.
interface IDeployer {
    /// @notice Emitted when a contract is successfully deployed.
    /// @param addr The address of the newly deployed contract.
    event Deploy(address addr);

    /// @notice Deploys a contract using CREATE3 with the provided bytecode and salt.
    /// @dev Reverts if the deployment fails (i.e., the deployed address has no code).
    /// @param bytecode The creation bytecode of the contract to deploy.
    /// @param salt The salt used to determine the deployed address.
    /// @return The address of the newly deployed contract.
    function deploy(
        bytes memory bytecode,
        bytes32 salt
    ) external returns (address);

    /// @notice Predicts the deterministic address for a given salt.
    /// @param salt The salt used to determine the deployed address.
    /// @return The predicted address.
    function predictAddress(bytes32 salt) external view returns (address);
}
