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

import {IPaymaster, PackedUserOperation} from
    "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";

/// @title IQuipPaymaster
/// @notice A UUPS-upgradeable ERC-4337 verifying paymaster that sponsors gas for QuipWallet
///         operations by validating an off-chain ECDSA approval from a trusted backend signer.
interface IQuipPaymaster is IPaymaster {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERRORS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when the verifier address is zero.
    error ZeroAddressVerifier();

    /// @notice Thrown when the owner address is zero.
    error ZeroAddressOwner();

    /// @notice Thrown when the caller is not the EntryPoint.
    error InvalidEntryPoint();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when the paymaster is initialized.
    /// @param owner The initial owner address.
    /// @param verifier The initial trusted backend signer.
    event PaymasterInitialized(address indexed owner, address indexed verifier);

    /// @notice Emitted when the trusted verifier is updated.
    /// @param oldVerifier The previous verifier address.
    /// @param newVerifier The new verifier address.
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         FUNCTIONS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Initializes the paymaster with an owner and a trusted verifier.
    /// @dev Can only be called once via the proxy. Uses Solady's `initializer` modifier.
    /// @param owner_ The initial owner address (receives admin privileges).
    /// @param verifier_ The trusted backend signer that approves gas sponsorship.
    function initialize(address owner_, address verifier_) external;

    /// @notice Updates the trusted backend signer.
    /// @dev Only callable by the owner. Reverts if `newVerifier` is the zero address.
    /// @param newVerifier The new verifier address.
    function setVerifier(address newVerifier) external;

    /// @notice Deposits ETH to the EntryPoint on behalf of this paymaster.
    /// @dev Anyone can call this to top up the paymaster's EntryPoint deposit.
    function deposit() external payable;

    /// @notice Withdraws ETH from the paymaster's EntryPoint deposit.
    /// @dev Only callable by the owner.
    /// @param to The recipient of the withdrawn ETH.
    /// @param amount The amount to withdraw in wei.
    function withdrawTo(address payable to, uint256 amount) external;

    /// @notice Stakes ETH with the EntryPoint for reputation.
    /// @dev Only callable by the owner. Required by the EntryPoint's reputation system.
    /// @param unstakeDelaySec The minimum delay (in seconds) before the stake can be withdrawn.
    function addStake(uint32 unstakeDelaySec) external payable;

    /// @notice Begins the unstake delay period for the paymaster's EntryPoint stake.
    /// @dev Only callable by the owner.
    function unlockStake() external;

    /// @notice Withdraws the paymaster's stake from the EntryPoint after the unstake delay.
    /// @dev Only callable by the owner. The stake must have been unlocked first.
    /// @param to The recipient of the withdrawn stake.
    function withdrawStake(address payable to) external;

    /// @notice Returns the paymaster's current ETH deposit at the EntryPoint.
    /// @return The deposit balance in wei.
    function getDeposit() external view returns (uint256);

    /// @notice Returns the current trusted backend signer address.
    /// @return The verifier address.
    function verifier() external view returns (address);
}
