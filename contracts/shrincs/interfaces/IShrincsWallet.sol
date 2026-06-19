// Copyright (C) 2026 quip.network
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

import {ShrincsTypes} from "@quip.network/hashsigs-solidity-0.1.0/contracts/ShrincsTypes.sol";

/// @title IShrincsWallet
/// @notice A smart-contract wallet whose operations are authorized by SHRINCS
///         hash-based signatures, providing post-quantum security for ETH transfers
///         and arbitrary calls. Normal operations use the cheap stateful path
///         (leaf-indexed, bounded by `maxSignatures`); break-glass recovery uses the
///         stateless path. A separate, dedicated stateless key backs ERC-1271.
interface IShrincsWallet {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ERRORS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when the factory address is zero.
    error ZeroAddressFactory();
    /// @notice Thrown when the owner address is zero.
    error ZeroAddressOwner();
    /// @notice Thrown when the caller is not the immutable factory.
    error InvalidFactory();

    /// @notice Thrown when a SHRINCS signature fails verification (stateful or stateless).
    error InvalidSignature();
    /// @notice Thrown when the supplied public-key bundle does not recompute to the
    ///         declared/installed commitment during `initialize`.
    error CommitmentMismatch();
    /// @notice Thrown when the supplied ERC-1271 verifier commitment is zero at install time.
    error ZeroErc1271Commitment();
    /// @notice Thrown when a decoded stateful public key declares `maxSignatures == 0`,
    ///         which can never produce a valid stateful signature.
    error ZeroMaxSignatures();

    /// @notice Thrown when a stateful signature's leaf index has already been consumed in the
    ///         current key epoch (used-leaf bitmap anti-replay).
    error StaleStatefulLeaf();
    /// @notice Thrown when a stateful signature's leaf index is zero or exceeds the installed
    ///         key's `maxSignatures` budget (the key must be rotated via `rotateKey`).
    error StatefulBudgetExhausted();
    /// @notice Thrown when the stateless break-glass budget (`statelessSignatureLimit`)
    ///         for the current key epoch is exhausted.
    error StatelessBudgetExhausted();

    /// @notice Thrown when `renounceOwnership` is called (always reverts).
    error RenounceDisabled();
    /// @notice Thrown when the classical `withdrawDepositTo(address,uint256)` is called directly.
    /// @dev Only the SHRINCS-authenticated `withdrawDepositTo(bytes)` path is permitted.
    error ClassicalWithdrawDisabled();
    /// @notice Thrown when the classical `transferOwnership(address)` is called directly.
    /// @dev Only the SHRINCS-authenticated `transferOwnership(bytes)` path is permitted.
    error ClassicalTransferOwnershipDisabled();
    /// @notice Thrown when any of Solady's inherited two-step ownership handover entry
    ///         points is called. This wallet supports only the SHRINCS-authenticated
    ///         `transferOwnership(bytes)` path, which cryptographically commits to `newOwner`.
    error OwnershipHandoverDisabled();

    /// @notice Thrown when the upgrade target's codehash is not in the factory's vetted set.
    error ImplementationNotVetted();
    /// @notice Thrown when the upgrade target's codehash has been deprecated.
    error ImplementationDeprecated();
    /// @notice Thrown when `migrate` is called outside the `upgradeToAndCall` context.
    error NotUpgrading();

    /// @notice Thrown when a delegatecall body (the `upgradeToAndCall` verify probe) modified one
    ///         of the eight slots the upgrade path snapshots and re-checks.
    /// @param slotIndex 0=owner, 1=ERC-1967 impl, 2=quipFactory, 3=shrincsPublicKeyCommitment,
    ///                  4=erc1271StatelessCommitment, 5=keyVersion, 6=nonce, 7=leaf-state word.
    error GuardedSlotTampered(uint256 slotIndex);
    /// @notice Thrown when `storageStore` is called. Raw storage writes are disabled because they
    ///         could clear consumed-leaf bits in the bitmap and re-enable one-time-signature replay.
    error StorageStoreDisabled();
    /// @notice Thrown when `delegateExecute` is called. Running un-vetted bytecode in the wallet's
    ///         storage context is disabled; use `executeBatch` for batching.
    error DelegateExecuteDisabled();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         EVENTS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when a wallet is initialized with its factory, owner, and SHRINCS keys.
    /// @param factory The QuipFactory that created this wallet.
    /// @param owner The classical owner address (ERC-1271 ECDSA gate + factory registry only).
    /// @param shrincsPublicKeyCommitment The installed main-key bundle commitment.
    /// @param erc1271StatelessCommitment The installed ERC-1271 verifier-key commitment.
    event WalletInitialized(
        address indexed factory,
        address indexed owner,
        bytes32 indexed shrincsPublicKeyCommitment,
        bytes32 erc1271StatelessCommitment
    );

    /// @notice Emitted when a stateful signature is consumed (its leaf marked used).
    /// @param leaf The consumed stateful leaf index.
    /// @param keyVersion The installed-key epoch the signature was valid under.
    event StatefulSignatureVerified(
        uint32 indexed leaf,
        uint256 indexed keyVersion
    );

    /// @notice Emitted in place of `ExecutionSucceeded` when `execute(bytes)` is signed with
    ///         `value == 0 && data.length == 0` — a deliberate leaf consumption with no call.
    /// @param leaf The consumed stateful leaf index.
    event LeafConsumedOnly(uint32 indexed leaf);

    /// @notice Emitted when an execution call succeeds.
    /// @param target The recipient or contract address.
    /// @param value The ETH value sent to the target.
    /// @param dataHash The keccak256 hash of the calldata.
    event ExecutionSucceeded(
        address indexed target,
        uint256 value,
        bytes32 dataHash
    );

    /// @notice Emitted when the dedicated ERC-1271 stateless verifier key is (re)installed.
    /// @param oldCommitment The previous ERC-1271 verifier commitment.
    /// @param newCommitment The installed ERC-1271 verifier commitment.
    event Erc1271KeySet(bytes32 oldCommitment, bytes32 newCommitment);

    /// @notice Emitted when the main SHRINCS key is rotated (stateful `rotateKey` or
    ///         stateless break-glass `recoverWallet`).
    /// @param previousCommitment The rotated-out main-key commitment.
    /// @param nextCommitment The installed main-key commitment.
    /// @param parameterSetId The installed key's parameter set.
    /// @param keyVersion The new installed-key epoch.
    event KeyRotated(
        bytes32 indexed previousCommitment,
        bytes32 indexed nextCommitment,
        uint8 parameterSetId,
        uint256 keyVersion
    );

    /// @notice Emitted when PQ state is migrated during an upgrade.
    /// @param shrincsPublicKeyCommitment The reinstalled main-key commitment.
    /// @param keyVersion The new installed-key epoch.
    event WalletMigrated(
        bytes32 indexed shrincsPublicKeyCommitment,
        uint256 keyVersion
    );

    /// @notice Discriminates the reasons `_validateSignature` returns `validationData == 1`.
    /// @dev Surfaced to off-chain simulators via `UserOpValidationRejected` since ERC-4337
    ///      forbids reverting with a reason from `validateUserOp`.
    enum UserOpValidationFailure {
        BadSignatureLength,
        StaleStatefulLeaf,
        StatefulBudgetExhausted,
        InvalidSignature
    }

    /// @notice Emitted on each `validationData == 1` exit of `_validateSignature`.
    /// @param reason The classification of the rejection.
    event UserOpValidationRejected(UserOpValidationFailure indexed reason);

    /// @notice Discriminates the reasons `isValidSignature` returns the ERC-1271 failure magic,
    ///         plus an `Ok` success sentinel surfaced by `debugIsValidSignature`.
    enum Erc1271ValidationResult {
        Ok,
        BadSignatureLength,
        InvalidEcdsaSignature,
        InvalidShrincsSignature
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Initializes the wallet. Called once by the factory.
    /// @param newOwner The classical owner (ERC-1271 ECDSA gate + factory registry only).
    /// @param payload Packed init data: `[0:32)` main commitment, `[32:64)` pkSeed, then the
    ///        ABI-encoded `(PublicKey mainBundle, uint8 parameterSetId, bytes32 erc1271Commitment,
    ///        uint8 erc1271ParameterSetId)`.
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) external;

    /// @notice Re-installs PQ state during an upgrade. Only valid inside `upgradeToAndCall`.
    function migrate(bytes calldata payload) external;

    /// @notice SHRINCS-gated UUPS upgrade. Authorized by a stateful signature from the main key.
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) external payable;

    /// @notice New-implementation reachability probe, delegatecalled during `upgradeToAndCall`.
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view;

    /// @notice Executes a single call authorized by a stateful SHRINCS signature.
    /// @param publicKey The main-key bundle (re-validated against the installed commitment).
    /// @param signature The stateful signature; its leaf must be unused in the current epoch.
    /// @param target The call target.
    /// @param value The ETH value to send.
    /// @param data The calldata to execute.
    function execute(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatefulSignature calldata signature,
        address target,
        uint256 value,
        bytes calldata data
    ) external payable;

    /// @notice Withdraws from the EntryPoint deposit, authorized by a stateful SHRINCS signature.
    function withdrawDepositTo(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatefulSignature calldata signature,
        address to,
        uint256 amount
    ) external payable;

    /// @notice Atomic full ownership handover to a new party. Installs an entirely FRESH key
    ///         bundle (new stateless recovery root) for the new owner AND sets the new classical
    ///         owner in one action, so the prior owner retains neither spend nor break-glass
    ///         authority. Requires BOTH: the current STATELESS recovery signature authorizing the
    ///         fresh bundle, and the current STATEFUL signature cross-binding `newOwner` to that
    ///         bundle (so the two cannot be mixed across attempts). Consumes one stateful leaf and
    ///         one stateless-budget unit; bumps the key epoch and notifies the factory registry.
    /// @param currentPublicKey The current main-key bundle (re-validated against the commitment).
    /// @param ownerBindingSignature Stateful signature over `(newOwner, nextKey.commitment)`.
    /// @param recoverySignature Stateless recovery signature authorizing the fresh bundle.
    /// @param nextKey The new owner's replacement full key bundle.
    /// @param newOwner The incoming classical owner (ERC-1271 ECDSA gate + factory registry).
    function transferOwnership(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatefulSignature calldata ownerBindingSignature,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey,
        address newOwner
    ) external payable;

    /// @notice (Re)installs the dedicated ERC-1271 stateless verifier key, authorized by a
    ///         stateful SHRINCS action from the main key.
    function setErc1271Key(
        ShrincsTypes.PublicKey calldata publicKey,
        ShrincsTypes.StatefulSignature calldata signature,
        bytes32 newErc1271Commitment,
        uint8 newErc1271ParameterSetId
    ) external payable;

    /// @notice Routine stateful rotation of the main key's stateful subkey (reusing the
    ///         stateless recovery root). Authorized by a stateful signature; resets the leaf
    ///         budget. Use before `maxSignatures` is exhausted.
    /// @param currentPublicKey The current main-key bundle (re-validated against the commitment).
    /// @param signature The stateful signature authorizing the rotation.
    /// @param nextStatefulKey The replacement stateful subkey target.
    function rotateKey(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatefulSignature calldata signature,
        ShrincsTypes.StatefulRotationTarget calldata nextStatefulKey
    ) external payable;

    /// @notice Break-glass wallet recovery: authorized by a STATELESS signature from the main
    ///         key's recovery half, it installs an entirely fresh key bundle (new stateful key
    ///         AND new stateless recovery root). Use when the stateful key is exhausted or
    ///         compromised. Ownership is unchanged; for a handover to a new party use
    ///         `transferOwnership`.
    /// @param currentPublicKey The current main-key bundle (re-validated against the commitment).
    /// @param recoverySignature The stateless recovery signature authorizing the rotation.
    /// @param nextKey The replacement full key bundle.
    function recoverWallet(
        ShrincsTypes.PublicKey calldata currentPublicKey,
        ShrincsTypes.StatelessSignature calldata recoverySignature,
        ShrincsTypes.RotationTarget calldata nextKey
    ) external payable;

    /// @notice Off-chain diagnostic variant of `isValidSignature` returning the failure branch.
    /// @dev ERC-1271 `isValidSignature(bytes32,bytes)` itself is inherited from the ERC1271 base
    ///      and overridden by the wallet (stateless SHRINCS verify against the dedicated verifier
    ///      key AND classical `owner()` ECDSA); it is not redeclared here to avoid an override clash.
    function debugIsValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (Erc1271ValidationResult);

    /// @notice The EIP-712 typed-data target the ERC-1271 ECDSA half must sign.
    function quipSignedHashEcdsaTarget(
        bytes32 hash
    ) external view returns (bytes32);

    /// @notice The classical owner (ERC-1271 ECDSA gate + factory registry).
    function owner() external view returns (address);

    /// @notice The factory's vetted-code index for this wallet's current implementation.
    function version() external view returns (uint256);

    /// @notice The per-operation execute fee charged by the factory.
    function getExecuteFee() external view returns (uint256);

    /// @notice The immutable factory address.
    function quipFactory() external view returns (address payable);

    /// @notice The installed main-key bundle commitment.
    function getShrincsPublicKeyCommitment() external view returns (bytes32);

    /// @notice The installed ERC-1271 verifier-key commitment.
    function getErc1271Commitment() external view returns (bytes32);

    /// @notice The installed main-key parameter set.
    function getParameterSetId()
        external
        view
        returns (ShrincsTypes.ParameterSetId);

    /// @notice The installed ERC-1271 verifier-key parameter set.
    function getErc1271ParameterSetId()
        external
        view
        returns (ShrincsTypes.ParameterSetId);

    /// @notice Whether stateful `leafIndex` has been consumed in the current key epoch.
    function isStatefulLeafUsed(uint256 leafIndex) external view returns (bool);

    /// @notice Count of stateful leaves consumed in the current key epoch.
    function statefulLeavesUsed() external view returns (uint32);

    /// @notice The installed main key's stateful signature budget.
    function maxSignatures() external view returns (uint32);

    /// @notice Stateful signatures remaining before the main key must be rotated.
    function remainingStatefulSignatures() external view returns (uint32);

    /// @notice The installed-key epoch.
    function keyVersion() external view returns (uint256);

    /// @notice The SHRINCS action/rotation nonce (distinct from the EntryPoint nonce).
    function actionNonce() external view returns (uint256);

    /// @notice Break-glass stateless rotations consumed under the current key epoch.
    function statelessSignaturesUsed() external view returns (uint64);

    /// @notice The profile's stateless signature limit for the current key epoch.
    function statelessSignatureLimit() external view returns (uint64);
}
