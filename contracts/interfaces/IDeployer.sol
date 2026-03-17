// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

/// @title IDeployer
/// @notice Deploys contracts with deterministic addresses across EVM chains using CREATE2.
interface IDeployer {
    /// @notice Emitted when a contract is successfully deployed.
    /// @param addr The address of the newly deployed contract.
    event Deploy(address addr);

    /// @notice Deploys a contract using CREATE2 with the provided bytecode and salt.
    /// @dev Reverts if the deployment fails (i.e., the deployed address has no code).
    /// @param bytecode The creation bytecode of the contract to deploy.
    /// @param salt The salt used to determine the deployed address.
    /// @return The address of the newly deployed contract.
    function deploy(bytes memory bytecode, uint256 salt) external returns (address);
}
