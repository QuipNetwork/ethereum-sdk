// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title IQuipWallet
/// @notice A smart-contract wallet whose operations are authorized by Winternitz one-time signatures,
///         providing post-quantum security for ETH transfers and arbitrary calls.
interface IQuipWallet {
    error UnauthorizedInitializer();
    error InvalidPqOwner();

    error InvalidSignature();

    error InsufficientBalance(uint256 requested, uint256 available);
    error RenounceDisabled();

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

    /// @notice Initializes the wallet with its first Winternitz public key.
    /// @dev Can only be called once, by the owner or the factory. Uses OpenZeppelin's `initializer` modifier.
    /// @param newPqOwner The Winternitz public key to set as the initial post-quantum owner.
    function initialize(WOTSPlus.WinternitzAddress calldata newPqOwner) external;

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
}
