// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title IQuipWallet
/// @notice A smart-contract wallet whose operations are authorized by Winternitz one-time signatures,
///         providing post-quantum security for ETH transfers and arbitrary calls.
interface IQuipWallet {
    error InvalidOwner();
    error InvalidPqOwner();

    error InvalidSignature();

    error InsufficientBalance(uint256 requested, uint256 available);
    error RenounceDisabled();

    error RecoveryKeyNotFound();
    error IncorrectRecoveryKeyAmount();
    error RecoveryKeyLimitExceeded();

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

    event WalletInitialized(
        address indexed factory,
        address indexed owner,
        WOTSPlus.WinternitzAddress pqOwner,
        WOTSPlus.WinternitzAddress[10] recoveryKeys
    );

    event pqRecovery(WOTSPlus.WinternitzAddress recoveryKey, WOTSPlus.WinternitzAddress newPqOwner);
    event RecoveryKeysReplenished(WOTSPlus.WinternitzAddress nextPqOwner);
    event RecoveryKeysAdded(WOTSPlus.WinternitzAddress nextPqOwner, uint256 count);

    /// @notice Initializes the wallet with its factory, classical owner, post-quantum owner, and recovery keys.
    /// @dev Can only be called once. Uses Solady's `initializer` modifier.
    ///      Payload layout: [0:64) pqOwner, [64:704) recoveryKeys (10 × 64).
    /// @param factory_ The QuipFactory address.
    /// @param newOwner The classical owner address.
    /// @param payload Packed init data: pqOwner ++ recoveryKeys[10].
    function initialize(
        address payable factory_,
        address payable newOwner,
        bytes calldata payload
    ) external;

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
    function pqOwner() external view returns (bytes32 publicSeed, bytes32 publicKeyHash);

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
    function getRecoveryKeyHashAt(uint256 index) external view returns (bytes32);

    /// @notice Returns whether a key hash is a registered recovery key.
    function isRecoveryKey(bytes32 keyHash) external view returns (bool);
}
