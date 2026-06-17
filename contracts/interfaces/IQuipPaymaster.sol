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

import {IPaymaster} from "@openzeppelin-contracts-5.6.0-rc.1/interfaces/draft-IERC4337.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title IQuipPaymaster
/// @notice A UUPS-upgradeable ERC-4337 verifying paymaster that sponsors gas for
///         WOTSPlusImplementation operations by validating a per-wallet WOTS+ signature
///         from a trusted backend signer.
///         Each sponsored wallet has its own WOTS+ verifier key chain, so key rotation
///         serializes per-wallet rather than globally.
///
///         The paymaster's WOTS+ digest is built from constituent UserOp fields (sender, nonce,
///         callData) rather than the EntryPoint's userOpHash. This avoids a circular dependency:
///         userOpHash includes paymasterAndData, which contains the paymaster's own signature.
interface IQuipPaymaster is IPaymaster {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ERRORS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when the owner address is zero.
    error ZeroAddressOwner();

    /// @notice Thrown when the caller is not the EntryPoint.
    error InvalidEntryPoint();

    /// @notice Thrown when a PQ verifier has zero-value publicSeed or publicKeyHash.
    error ZeroValuePqVerifierKey();

    /// @notice Thrown when attempting to remove a PQ verifier for a wallet that has none.
    error PqVerifierNotRegistered();

    /// @notice Thrown by `setPqVerifier` when the supplied verifier is already
    ///         registered as the verifier for some other wallet. Cross-wallet
    ///         reuse would let a single revealed WOTS+ signature burn both
    ///         wallets' verifiers, so installation is forbidden.
    error VerifierKeyInUse();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         EVENTS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when the paymaster is initialized.
    /// @param owner The initial owner address.
    event PaymasterInitialized(address indexed owner);

    /// @notice Emitted when a per-wallet WOTS+ verifier is set.
    /// @dev On first registration `oldVerifier` is the zero
    ///      `WinternitzAddress` (`publicSeed == 0 && publicKeyHash == 0`); on
    ///      admin hot-swap (re-binding an existing wallet to a new key)
    ///      `oldVerifier` carries the prior key so off-chain consumers can
    ///      distinguish first-set from override without keeping per-wallet
    ///      state across event history.
    /// @param wallet The wallet address the verifier is set for.
    /// @param oldVerifier The verifier previously bound to `wallet`, or the
    ///        zero address-pair if this is a first-time set / no-op re-bind
    ///        of the same key.
    /// @param newVerifier The newly-bound WOTS+ verifier.
    event PqVerifierSet(
        address indexed wallet,
        WOTSPlus.WinternitzAddress oldVerifier,
        WOTSPlus.WinternitzAddress newVerifier
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

    /// @notice Discriminates the four reasons `validatePaymasterUserOp` may
    ///         return `validationData == 1` (signature failure) to the EntryPoint.
    /// @dev Surfaced to off-chain simulators (`eth_call` / `debug_traceCall`)
    ///      via `PaymasterValidationRejected` since ERC-4337 forbids reverting
    ///      with a reason from `validatePaymasterUserOp`. Distinguishing
    ///      "no verifier registered" (config error), "key reuse" (replay
    ///      attempt), and "bad sig" (attack) is operationally critical for a
    ///      paymaster operator triaging failed sponsored UserOps.
    enum PaymasterValidationFailure {
        MalformedPayload,
        ZeroNextVerifier,
        NoVerifierRegistered,
        NextEqualsCurrent,
        NextVerifierKeyInUse,
        InvalidSignature
    }

    /// @notice Emitted on each `validationData == 1` exit of `_verifyAndRotate`.
    /// @dev On-chain this event is rolled back when the EntryPoint reverts the
    ///      UserOp on signature failure, but bundlers / simulators observe it
    ///      via `debug_traceCall` traces during pre-flight simulation.
    /// @param wallet The userOp.sender the rejection applies to.
    /// @param reason The classification of the rejection.
    event PaymasterValidationRejected(
        address indexed wallet,
        PaymasterValidationFailure indexed reason
    );

    /// @notice Emitted from `postOp` for every UserOp the paymaster sponsored.
    /// @dev Provides an on-chain audit trail of paymaster spend per wallet:
    ///      who was sponsored, whether the inner UserOp succeeded or reverted,
    ///      and how much gas the paymaster was charged. Used for off-chain
    ///      analytics, dispute resolution, and any future per-wallet policy.
    ///      Unlike `PaymasterValidationRejected`, this event survives in the
    ///      final block log because `postOp` runs after the validation/exec
    ///      phase that the EntryPoint can revert.
    /// @param wallet The userOp.sender that was sponsored.
    /// @param mode 0 = inner op succeeded, 1 = inner op reverted, 2 = re-entry
    ///        after a prior postOp call reverted.
    /// @param actualGasCost The wei amount the paymaster was charged.
    /// @param actualUserOpFeePerGas The gas price the EntryPoint used.
    event UserOpSponsored(
        address indexed wallet,
        PostOpMode indexed mode,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    );

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

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
