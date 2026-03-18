// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title IQuipFactory
/// @notice Factory for creating and managing QuipWallet instances secured by Winternitz one-time signatures.
interface IQuipFactory {
    /// @notice Emitted when a new QuipWallet is created.
    /// @param amount The ETH value sent with the creation transaction.
    /// @param when The block timestamp at which the wallet was created.
    /// @param vaultId The salt used to derive the wallet's CREATE2 address.
    /// @param creator The classical address that owns the new wallet.
    /// @param pqPubkey The post-quantum Winternitz public key assigned to the wallet.
    /// @param quip The address of the newly deployed QuipWallet.
    event QuipCreated(
        uint256 amount,
        uint256 when,
        bytes32 vaultId,
        address creator,
        WOTSPlus.WinternitzAddress pqPubkey,
        address quip
    );

    /// @notice Deploys a new QuipWallet via CREATE2, initializes it with a Winternitz public key,
    ///         and forwards the deposited ETH (minus the creation fee) to the wallet.
    /// @dev Reverts if the CREATE2 deployment fails or if `msg.value` is less than `creationFee`.
    /// @param vaultId The salt used to derive the wallet's deterministic address.
    /// @param to The classical address that will own the new wallet.
    /// @param pqTo The Winternitz public key to initialize the wallet with.
    /// @return The address of the newly deployed QuipWallet.
    function depositToWinternitz(
        bytes32 vaultId,
        address payable to,
        WOTSPlus.WinternitzAddress calldata pqTo
    ) external payable returns (address);

    /// @notice Sets the fee charged when creating a new QuipWallet.
    /// @dev Only callable by the current admin.
    /// @param newFee The new creation fee in wei.
    function setCreationFee(uint256 newFee) external;

    /// @notice Sets the fee charged on Winternitz-authenticated transfers.
    /// @dev Only callable by the current admin.
    /// @param newFee The new transfer fee in wei.
    function setTransferFee(uint256 newFee) external;

    /// @notice Sets the fee charged on Winternitz-authenticated arbitrary calls.
    /// @dev Only callable by the current admin.
    /// @param newFee The new execute fee in wei.
    function setExecuteFee(uint256 newFee) external;

    /// @notice Withdraws accumulated fees from the factory to the admin.
    /// @dev Only callable by the current admin. Reverts if the factory balance is insufficient.
    /// @param amount The amount of ETH in wei to withdraw.
    function withdraw(uint256 amount) external;

    /// @notice Returns the address of the deployed WOTSPlus library.
    /// @return The WOTSPlus library address.
    function wotsLibrary() external view returns (address);

    /// @notice Returns the current fee charged for wallet creation.
    /// @return The creation fee in wei.
    function creationFee() external view returns (uint256);

    /// @notice Returns the current fee charged for Winternitz-authenticated transfers.
    /// @return The transfer fee in wei.
    function transferFee() external view returns (uint256);

    /// @notice Returns the current fee charged for Winternitz-authenticated arbitrary calls.
    /// @return The execute fee in wei.
    function executeFee() external view returns (uint256);

    /// @notice Returns the QuipWallet address for a given owner and vault ID.
    /// @param owner The classical owner address.
    /// @param vaultId The vault identifier.
    /// @return The QuipWallet address, or `address(0)` if none exists.
    function quips(address owner, bytes32 vaultId) external view returns (address);

    /// @notice Returns the vault ID at a given index for an owner.
    /// @param owner The classical owner address.
    /// @param index The index into the owner's vault ID array.
    /// @return The vault ID at the specified index.
    function vaultIds(address owner, uint256 index) external view returns (bytes32);
}
