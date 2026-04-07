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

/// @title IQuipWallet
/// @notice A smart-contract wallet whose operations are authorized by Winternitz one-time signatures,
///         providing post-quantum security for ETH transfers and arbitrary calls.
interface IQuipWallet {
    /// @notice Thrown when the factory address is zero.
    error ZeroAddressFactory();
    /// @notice Thrown when the owner address is zero.
    error ZeroAddressOwner();
    /// @notice Thrown when the caller is not the immutable factory.
    error InvalidFactory();
    /// @notice Thrown when a Winternitz public key has zero-value components.
    error ZeroValuePqOwner();

    /// @notice Thrown when a Winternitz signature fails verification.
    error InvalidSignature();

    /// @notice Thrown when the wallet balance is insufficient for the requested operation.
    /// @param requested The amount required.
    /// @param available The current balance.
    error InsufficientBalance(uint256 requested, uint256 available);
    /// @notice Thrown when `renounceOwnership` is called (always reverts).
    error RenounceDisabled();

    /// @notice Thrown when a recovery key is not in the registered set.
    error RecoveryKeyNotFound();
    /// @notice Thrown when the number of recovery keys provided is incorrect.
    error IncorrectRecoveryKeyAmount();
    /// @notice Thrown when adding recovery keys would exceed `MAX_RECOVERY_KEYS`.
    error RecoveryKeyLimitExceeded();
    /// @notice Thrown when `migrate` is called outside the `upgradeToAndCall` context.
    error NotUpgrading();
    /// @notice Thrown when upgradeToAndCall would reuse the current pqOwner key.
    error PqOwnerReuse();
    /// @notice Thrown when a duplicate recovery key is provided.
    error DuplicateRecoveryKey();
    /// @notice Thrown when an empty recovery key array is provided.
    error EmptyRecoveryKeys();

    /// @notice Thrown when the upgrade target's codehash is not in the factory's vetted set.
    error ImplementationNotVetted();
    /// @notice Thrown when the upgrade target's codehash has been deprecated.
    error ImplementationDeprecated();

    /// @notice Emitted when the post-quantum owner key is rotated.
    /// @param oldPqOwner The previous Winternitz public key.
    /// @param newPqOwner The new Winternitz public key.
    event PqOwnerRotated(
        WOTSPlus.WinternitzAddress oldPqOwner,
        WOTSPlus.WinternitzAddress newPqOwner
    );

    /// @notice Emitted when an execution call succeeds.
    /// @param target The recipient or contract address.
    /// @param value The ETH value sent to the target.
    /// @param dataHash The keccak256 hash of the calldata.
    event ExecutionSucceeded(address target, uint256 value, bytes32 dataHash);

    /// @notice Emitted when a wallet is initialized with its factory, owner, and keys.
    /// @param factory The QuipFactory that created this wallet.
    /// @param owner The classical owner address.
    /// @param pqOwner The initial post-quantum owner key.
    /// @param recoveryKeys The initial set of 10 recovery keys.
    event WalletInitialized(
        address indexed factory,
        address indexed owner,
        WOTSPlus.WinternitzAddress pqOwner,
        WOTSPlus.WinternitzAddress[10] recoveryKeys
    );

    /// @notice Emitted when the wallet is recovered using a recovery key.
    /// @param recoveryKey The recovery key that authorized the recovery.
    /// @param newPqOwner The new post-quantum owner key set during recovery.
    event PqRecovery(
        WOTSPlus.WinternitzAddress recoveryKey,
        WOTSPlus.WinternitzAddress newPqOwner
    );
    /// @notice Emitted when all recovery keys are cleared and replaced.
    /// @param nextPqOwner The new post-quantum owner key after rotation.
    event RecoveryKeysReplenished(WOTSPlus.WinternitzAddress nextPqOwner);
    /// @notice Emitted when new recovery keys are added to the existing set.
    /// @param nextPqOwner The new post-quantum owner key after rotation.
    /// @param count The number of recovery keys added.
    event RecoveryKeysAdded(
        WOTSPlus.WinternitzAddress nextPqOwner,
        uint256 count
    );


    /// @notice Emitted when PQ state is migrated during an upgrade.
    /// @param newPqOwner The new post-quantum owner key set during migration.
    event WalletMigrated(WOTSPlus.WinternitzAddress newPqOwner);

    /// @notice Emitted when a recovery key authorizes an emergency implementation upgrade.
    /// @param newImplementation The new implementation address.
    /// @param recoveryKey The recovery key that authorized the upgrade.
    event RecoveryUpgrade(
        address indexed newImplementation,
        WOTSPlus.WinternitzAddress recoveryKey
    );

    /// @notice Emitted when the inner call of an ERC-4337 execution reverts but key rotation commits.
    /// @param target The target of the failed call.
    /// @param value The ETH value attempted.
    /// @param dataHash The keccak256 hash of the calldata.
    /// @param result The revert data from the failed call.
    event ExecutionReverted(address target, uint256 value, bytes32 dataHash, bytes result);

    /// @notice Disabled; always reverts with `RenounceDisabled`.
    function renounceOwnership() external payable;

    /// @notice Upgrades the wallet to a new implementation, verifying two PQ signatures and
    ///         optionally migrating state.
    /// @dev First verifies the upgrade authorization against the current pqOwner using pqSig.
    ///      Then delegatecalls `verifyUpgrade` on the new implementation, which independently
    ///      verifies a second signature from the verifier key embedded in the payload.
    ///      Optionally calls `migrate` if the payload includes migration data. Finally delegates
    ///      to the parent `upgradeToAndCall` with empty calldata.
    /// @param newImplementation The address of the new implementation contract.
    /// @param data Packed upgrade data: [0:64) nextPqOwner, [64:2208) pqSig,
    ///      [2208:2272) verifier, [2272:4416) verifySig,
    ///      [4416] shouldMigrate, [4417:5121) migratorPayload.
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) external payable;

    /// @notice Verifies a PQ signature from the new implementation's verifier key.
    /// @dev MUST be called on every upgrade — `upgradeToAndCall` delegates to this function
    ///      on the new implementation. The verifier key and signature are extracted via
    ///      `decodeUpgradeVerification` and verified against a `verificationDigest`. Future
    ///      implementations may use a different PQ scheme for this step.
    /// @param newImplementation The address of the new implementation being upgraded to.
    /// @param data Packed upgrade payload; verifier at [2208:2272), verifySig at [2272:4416).
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view;

    /// @notice Verifies an implementation is vetted and not deprecated during a recovery upgrade.
    /// @dev Called via delegatecall from `recoveryUpgrade` on the new implementation.
    /// @param newImplementation The address of the new implementation being upgraded to.
    /// @param data Packed recovery upgrade payload.
    function verifyRecoveryUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view;

    /// @notice Initializes the wallet with its classical owner, post-quantum owner, and recovery keys.
    /// @dev Can only be called once by the FACTORY. Uses Solady's `initializer` modifier.
    ///      Payload layout: [0:64) pqOwner, [64:704) recoveryKeys (10 × 64).
    /// @param newOwner The classical owner address.
    /// @param payload Packed init data: pqOwner ++ recoveryKeys[10].
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) external;

    /// @notice Re-initializes the PQ state (pqOwner + recovery keys) during an upgrade.
    /// @dev Only callable by the classical owner. Called via delegatecall from upgradeToAndCall
    ///      so that it executes against proxy storage.
    ///      Payload layout: [0:64) new pqOwner, [64:704) new recoveryKeys[10].
    /// @param payload Packed migration data matching the init layout.
    function migrate(bytes calldata payload) external;

    /// @notice Rotates the post-quantum owner key to a new Winternitz public key.
    /// @dev Only callable by the classical owner. The signature must be valid over the
    ///      concatenation of the current and new public key components.
    ///      Payload layout: [0:64) newPqOwner, [64:2208) pqSig.
    /// @param payload Packed changePqOwner data (2208 bytes).
    function changePqOwner(bytes calldata payload) external;

    /// @notice Executes a post-quantum authenticated operation: either a pure ETH transfer
    ///         or an arbitrary contract call.
    /// @dev Only callable by the classical owner. The fee is deducted from the wallet balance
    ///      and sent to the factory. For pure transfers (data is empty), uses SafeTransferLib.
    ///      For contract calls (data is non-empty), uses LibCall.callContract.
    ///      Rotates the post-quantum owner key to `nextPqOwner` upon success.
    ///      Payload layout: [0:64) nextPqOwner, [64:2208) pqSig,
    ///      [2208:2240) target, [2240:2272) value, [2272:...) data.
    /// @param payload Packed execute data (>= 2272 bytes).
    /// @return The data returned by the call (empty for pure transfers).
    function execute(bytes calldata payload) external payable returns (bytes memory);

    /// @notice Returns the current execute fee as set by the factory.
    /// @return The execute fee in wei.
    function getExecuteFee() external view returns (uint256);

    /// @notice Returns the address of the QuipFactory that created this wallet.
    /// @return The factory address.
    function quipFactory() external view returns (address payable);

    /// @notice Returns the current post-quantum owner's Winternitz public key components.
    /// @return publicSeed The public seed of the Winternitz address.
    /// @return publicKeyHash The public key hash of the Winternitz address.
    function pqOwner()
        external
        view
        returns (bytes32 publicSeed, bytes32 publicKeyHash);

    /// @notice Recovers the wallet using a pre-registered recovery key.
    /// @dev Payload layout: [0:64) recoveryKey, [64:128) newPqOwner, [128:2272) pqSig.
    /// @param payload Packed recoverWallet data (2272 bytes).
    function recoverWallet(bytes calldata payload) external;

    /// @notice Adds new recovery keys to the existing set.
    /// @dev Payload layout: [0:64) nextPqOwner, [64:2208) pqSig, [2208:...) keys (N x 64).
    /// @param payload Packed keyManagement data (>= 2208 bytes).
    function addRecoveryKeys(bytes calldata payload) external;

    /// @notice Clears existing recovery keys and adds new ones.
    /// @dev Payload layout: [0:64) nextPqOwner, [64:2208) pqSig, [2208:...) keys (N x 64).
    /// @param payload Packed keyManagement data (>= 2208 bytes).
    function replenishRecoveryKeys(bytes calldata payload) external;

    /// @notice Emergency upgrade authorized by a recovery key, without migration.
    /// @dev Delegatecalls `verifyRecoveryUpgrade` on the new implementation to vet it,
    ///      then verifies the recovery key's signature and spends the key.
    ///      No pqOwner rotation or migration is performed.
    ///      Payload layout: [0:64) recoveryKey, [64:2208) pqSig.
    /// @param newImplementation The address of the new implementation contract.
    /// @param payload Packed recovery upgrade data (2208 bytes).
    function recoveryUpgrade(
        address newImplementation,
        bytes calldata payload
    ) external;

    /// @notice Returns the number of recovery keys in the set.
    /// @return The number of registered recovery key hashes.
    function getRecoveryKeyCount() external view returns (uint256);

    /// @notice Returns the recovery key hash at a given index.
    /// @return The keccak256 hash of the recovery key at the given index.
    function getRecoveryKeyHashAt(
        uint256 index
    ) external view returns (bytes32);

    /// @notice Returns whether a key hash is a registered recovery key.
    /// @return True if the key hash is a registered recovery key.
    function isRecoveryKey(bytes32 keyHash) external view returns (bool);

    /// @notice Returns the implementation version of this wallet.
    /// @dev Reads the ERC-1967 implementation slot and queries the factory for
    ///      the index of its codehash in the vetted set.
    /// @return The index in the factory's vetted set, or `type(uint256).max` if not found.
    function version() external view returns (uint256);
}
