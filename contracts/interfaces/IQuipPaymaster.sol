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

import {IPaymaster, PackedUserOperation} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title IQuipPaymaster
/// @notice A UUPS-upgradeable ERC-4337 verifying paymaster that sponsors gas for QuipWallet
///         operations by validating a per-wallet WOTS+ signature from a trusted backend signer.
///         Each sponsored wallet has its own WOTS+ verifier key chain, so key rotation
///         serializes per-wallet rather than globally.
///
///         The paymaster's WOTS+ digest is built from constituent UserOp fields (sender, nonce,
///         callData) rather than the EntryPoint's userOpHash. This avoids a circular dependency:
///         userOpHash includes paymasterAndData, which contains the paymaster's own signature.
interface IQuipPaymaster is IPaymaster {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           ERRORS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when the owner address is zero.
    error ZeroAddressOwner();

    /// @notice Thrown when the caller is not the EntryPoint.
    error InvalidEntryPoint();

    /// @notice Thrown when a PQ verifier has zero-value publicSeed or publicKeyHash.
    error ZeroValuePqVerifierKey();

    /// @notice Thrown when attempting to remove a PQ verifier for a wallet that has none.
    error PqVerifierNotRegistered();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when the paymaster is initialized.
    /// @param owner The initial owner address.
    event PaymasterInitialized(address indexed owner);

    /// @notice Emitted when a per-wallet WOTS+ verifier is set.
    /// @param wallet The wallet address the verifier is set for.
    /// @param verifier The WOTS+ verifier.
    event PqVerifierSet(
        address indexed wallet,
        WOTSPlus.WinternitzAddress verifier
    );

    /// @notice Emitted when a per-wallet WOTS+ verifier key is removed.
    /// @param wallet The wallet address whose verifier was removed.
    event PqVerifierRemoved(address indexed wallet);

    /// @notice Emitted when a per-wallet WOTS+ verifier is rotated during validation.
    /// @param wallet The wallet address whose verifier was rotated.
    /// @param currentVerifier The previous WOTS+ verifier (emitted before storage update).
    /// @param nextVerifier The new WOTS+ verifier.
    event PqVerifierRotated(
        address indexed wallet,
        WOTSPlus.WinternitzAddress currentVerifier,
        WOTSPlus.WinternitzAddress nextVerifier
    );

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         FUNCTIONS                             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Initializes the paymaster with an owner.
    /// @dev Can only be called once via the proxy. Uses Solady's `initializer` modifier.
    /// @param owner_ The initial owner address (receives admin privileges).
    function initialize(address owner_) external;

    /// @notice Sets the WOTS+ verifier for a specific wallet.
    /// @dev Only callable by the owner. Overwrites any existing verifier.
    ///      Reverts if the verifier has zero-value fields.
    /// @param wallet The wallet address to set a verifier for.
    /// @param verifier The WOTS+ verifier.
    function setPqVerifier(
        address wallet,
        WOTSPlus.WinternitzAddress calldata verifier
    ) external;

    /// @notice Removes the WOTS+ verifier key for a specific wallet.
    /// @dev Only callable by the owner. Reverts if the wallet has no verifier.
    /// @param wallet The wallet address to remove the verifier for.
    function removePqVerifier(address wallet) external;

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

    /// @notice Returns the WOTS+ verifier for a specific wallet.
    /// @param wallet The wallet address to query.
    /// @return The verifier's WinternitzAddress (zero if none set).
    function getPqVerifier(
        address wallet
    ) external view returns (WOTSPlus.WinternitzAddress memory);
}
