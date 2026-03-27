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

    /// @notice Emitted when a post-quantum authenticated transfer or execution occurs.
    /// @param amount The ETH value transferred.
    /// @param when The block timestamp of the transfer.
    /// @param pqFrom The Winternitz public key that authorized the operation.
    /// @param pqNext The new Winternitz public key that replaces `pqFrom`.
    /// @param to The recipient address.
    event pqTransfer(
        uint256 amount,
        uint256 when,
        WOTSPlus.WinternitzAddress pqFrom,
        WOTSPlus.WinternitzAddress pqNext,
        address to
    );

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
    event pqRecovery(
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

    /// @notice Disabled; always reverts with `RenounceDisabled`.
    function renounceOwnership() external payable;

    /// @notice Upgrades the wallet to a new implementation, verifying a PQ signature and
    ///         optionally migrating state.
    /// @dev Calls `verifyUpgrade` on the new implementation via delegatecall, then optionally
    ///      calls `migrate` if the payload includes migration data. Finally delegates to the
    ///      parent `upgradeToAndCall` with empty calldata.
    /// @param newImplementation The address of the new implementation contract.
    /// @param data Packed upgrade data: [0:64) pqSigner, [64:2208) pqSig, [2208:...) optional migration payload.
    function upgradeToAndCall(
        address newImplementation,
        bytes calldata data
    ) external payable;

    /// @notice Verifies a PQ signature authorizing an upgrade to a new implementation.
    /// @dev MUST be called on every upgrade — `upgradeToAndCall` delegates to this function
    ///      on the new implementation to ensure the upgrade is authorized by the current
    ///      post-quantum owner. New implementations that omit this function will cause
    ///      upgrades to revert.
    ///      Data layout: [0:64) pqSigner (WinternitzAddress), [64:2208) pqSig (WinternitzElements).
    /// @param newImplementation The address of the new implementation being upgraded to.
    /// @param data Packed verification data containing the PQ signer and signature.
    function verifyUpgrade(
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
    /// @param newPqOwner The new Winternitz public key to replace the current one.
    /// @param pqSig The Winternitz signature proving authorization from the current post-quantum owner.
    function changePqOwner(
        WOTSPlus.WinternitzAddress calldata newPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig
    ) external;

    /// @notice Transfers ETH from the wallet to a recipient, authorized by a Winternitz signature.
    /// @dev Only callable by the classical owner. Requires `msg.value >= transferFee`.
    ///      The signature must be valid over the concatenation of the current and next public key
    ///      components, the recipient address, and the transfer value. Rotates the post-quantum
    ///      owner key to `nextPqOwner` upon success.
    /// @param nextPqOwner The new Winternitz public key to replace the current one after the transfer.
    /// @param pqSig The Winternitz signature proving authorization from the current post-quantum owner.
    /// @param to The recipient address.
    /// @param value The amount of ETH in wei to transfer from the wallet.
    function transferWithWinternitz(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable to,
        uint256 value
    ) external payable;

    /// @notice Executes an arbitrary call from the wallet, authorized by a Winternitz signature.
    /// @dev Only callable by the classical owner. Requires `msg.value >= executeFee`.
    ///      The fee is sent to the factory; the remaining `msg.value` is forwarded to the target.
    ///      Rotates the post-quantum owner key to `nextPqOwner` upon success.
    /// @param nextPqOwner The new Winternitz public key to replace the current one after execution.
    /// @param pqSig The Winternitz signature proving authorization from the current post-quantum owner.
    /// @param target The contract address to call.
    /// @param opdata The calldata to pass to the target.
    /// @return returnData The data returned by the call.
    function executeWithWinternitz(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        address payable target,
        bytes calldata opdata
    ) external payable returns (bytes memory returnData);

    /// @notice Returns the current transfer fee as set by the factory.
    /// @return The transfer fee in wei.
    function getTransferFee() external view returns (uint256);

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
    /// @param recoveryKey The recovery key to use (must be in the set).
    /// @param newPqOwner The new post-quantum owner key to set.
    /// @param pqSig The Winternitz signature from the recovery key.
    function recoverWallet(
        WOTSPlus.WinternitzAddress calldata recoveryKey,
        WOTSPlus.WinternitzAddress calldata newPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig
    ) external;

    /// @notice Adds new recovery keys to the existing set.
    /// @param nextPqOwner The new post-quantum owner key after rotation.
    /// @param pqSig The Winternitz signature from the current pqOwner.
    /// @param newRecoveryKeys The recovery keys to add.
    function addRecoveryKeys(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
    ) external;

    /// @notice Clears existing recovery keys and adds new ones.
    /// @param nextPqOwner The new post-quantum owner key after rotation.
    /// @param pqSig The Winternitz signature from the current pqOwner.
    /// @param newRecoveryKeys The new recovery keys to set.
    function replenishRecoveryKeys(
        WOTSPlus.WinternitzAddress calldata nextPqOwner,
        WOTSPlus.WinternitzElements calldata pqSig,
        WOTSPlus.WinternitzAddress[] calldata newRecoveryKeys
    ) external;

    /// @notice Returns the number of recovery keys in the set.
    function getRecoveryKeyCount() external view returns (uint256);

    /// @notice Returns the recovery key hash at a given index.
    function getRecoveryKeyHashAt(
        uint256 index
    ) external view returns (bytes32);

    /// @notice Returns whether a key hash is a registered recovery key.
    function isRecoveryKey(bytes32 keyHash) external view returns (bool);
}
