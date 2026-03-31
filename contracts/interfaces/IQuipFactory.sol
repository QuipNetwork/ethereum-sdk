// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.1.0/contracts/WOTSPlus.sol";

/// @title IQuipFactory
/// @notice Factory for creating and managing QuipWallet proxies secured by Winternitz one-time signatures.
///         Supports multiple vetted implementation versions with index-based selection.
interface IQuipFactory {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          ERRORS                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when the factory balance is insufficient for the requested withdrawal.
    /// @param requested The amount requested.
    /// @param available The current balance.
    error InsufficientBalance(uint256 requested, uint256 available);
    /// @notice Thrown when a fee exceeds the maximum allowed.
    /// @param fee The fee that was set.
    /// @param maxFee The maximum allowed fee.
    error FeeExceedsMax(uint256 fee, uint256 maxFee);

    /// @notice Thrown when the implementation address has no deployed code.
    error EmptyCode();
    /// @notice Thrown when the implementation's codehash is not in the vetted set.
    error ImplementationNotVetted();
    /// @notice Thrown when attempting to deploy with a deprecated implementation.
    error ImplementationDeprecated();
    /// @notice Thrown when no active (non-deprecated) implementation exists.
    error NoActiveImplementation();
    /// @notice Thrown when msg.value is less than the creation fee.
    /// @param sent The ETH value sent.
    /// @param required The required creation fee.
    error InsufficientCreationFee(uint256 sent, uint256 required);
    /// @notice Thrown when `renounceOwnership` is called (always reverts).
    error RenounceDisabled();
    /// @notice Thrown when the max fee is zero.
    error ZeroMaxFee();
    /// @notice Thrown when the wallet owner address is zero.
    error ZeroAddressOwner();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          EVENTS                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when an implementation is vetted or re-activated.
    /// @param impl The implementation contract address.
    /// @param codehash The codehash of the implementation.
    event ImplementationVetted(address indexed impl, bytes32 codehash);

    /// @notice Emitted when an implementation is deprecated.
    /// @param impl The implementation contract address.
    /// @param codehash The codehash of the implementation.
    event ImplementationSunset(address indexed impl, bytes32 codehash);

    /// @notice Emitted when the creation fee is updated.
    /// @param oldFee The previous creation fee.
    /// @param newFee The new creation fee.
    event CreationFeeUpdated(uint256 oldFee, uint256 newFee);

    /// @notice Emitted when the execute fee is updated.
    /// @param oldFee The previous execute fee.
    /// @param newFee The new execute fee.
    event ExecuteFeeUpdated(uint256 oldFee, uint256 newFee);

    /// @notice Emitted when a new QuipWallet proxy is created.
    /// @param amount The ETH value sent with the creation transaction.
    /// @param when The block timestamp at which the wallet was created.
    /// @param vaultId The salt used to derive the wallet's deterministic address.
    /// @param creator The classical address that owns the new wallet.
    /// @param pqPubkey The post-quantum Winternitz public key assigned to the wallet.
    /// @param quip The address of the newly deployed QuipWallet proxy.
    event QuipCreated(
        uint256 amount,
        uint256 when,
        bytes32 vaultId,
        address creator,
        WOTSPlus.WinternitzAddress pqPubkey,
        address quip
    );

    /// @notice Emitted when ETH is withdrawn from the factory.
    /// @param to The address that received the withdrawal.
    /// @param amount The amount of ETH withdrawn.
    event Withdrawn(address indexed to, uint256 amount);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       FUNCTIONS                               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Approves an implementation's codehash for proxy deployment.
    /// @dev Only callable by the admin. Computes `extcodehash` of `impl` and adds it
    ///      to the vetted set. If the codehash was previously deprecated, re-activates it.
    /// @param impl The deployed implementation contract address.
    function vetImplementation(address impl) external;

    /// @notice Marks an implementation's codehash as deprecated.
    /// @dev Only callable by the admin. The codehash remains in the set (preserving indices)
    ///      but cannot be used for new proxy deployments until re-vetted.
    /// @param impl The deployed implementation contract address.
    function deprecateImplementation(address impl) external;

    /// @notice Deploys a new QuipWallet proxy using the latest active implementation,
    ///         initializes it, and forwards deposited ETH (minus creation fee) to the wallet.
    /// @dev Iterates backwards through the vetted set to find the most recently added
    ///      non-deprecated implementation. Uses CREATE3 for deterministic addressing.
    /// @param vaultId The salt used to derive the wallet's deterministic address.
    /// @param to The classical address that will own the new wallet.
    /// @param payload Packed init data: [0:64) pqOwner, [64:704) recoveryKeys[10].
    /// @return The address of the newly deployed QuipWallet proxy.
    function deployLatestWalletProxy(
        bytes32 vaultId,
        address payable to,
        bytes calldata payload
    ) external payable returns (address);

    /// @notice Deploys a new QuipWallet proxy using the implementation at a specific index,
    ///         initializes it, and forwards deposited ETH (minus creation fee) to the wallet.
    /// @dev The index corresponds to insertion order in the vetted set. Reverts if the
    ///      implementation at the given index is deprecated.
    /// @param vaultId The salt used to derive the wallet's deterministic address.
    /// @param index The index into the vetted implementation set.
    /// @param to The classical address that will own the new wallet.
    /// @param payload Packed init data: [0:64) pqOwner, [64:704) recoveryKeys[10].
    /// @return The address of the newly deployed QuipWallet proxy.
    function deploySpecificWalletProxy(
        bytes32 vaultId,
        uint256 index,
        address payable to,
        bytes calldata payload
    ) external payable returns (address);

    /// @notice Sets the fee charged when creating a new QuipWallet.
    /// @dev Only callable by the current admin.
    /// @param newFee The new creation fee in wei.
    function setCreationFee(uint256 newFee) external;

    /// @notice Sets the fee charged on Winternitz-authenticated operations.
    /// @dev Only callable by the current admin.
    /// @param newFee The new execute fee in wei.
    function setExecuteFee(uint256 newFee) external;

    /// @notice Withdraws accumulated fees from the factory to the admin.
    /// @dev Only callable by the current admin. Reverts if the factory balance is insufficient.
    /// @param amount The amount of ETH in wei to withdraw.
    function withdraw(uint256 amount) external;

    /// @notice Disabled; always reverts with `RenounceDisabled`.
    function renounceOwnership() external;

    /// @notice Returns the current fee charged for wallet creation.
    /// @return The creation fee in wei.
    function creationFee() external view returns (uint256);

    /// @notice Returns the current fee charged for Winternitz-authenticated operations.
    /// @return The execute fee in wei.
    function executeFee() external view returns (uint256);

    /// @notice Returns the maximum fee that can be set.
    /// @return The maximum fee in wei.
    function MAX_FEE() external view returns (uint256);

    /// @notice Returns the QuipWallet address for a given owner and vault ID.
    /// @param owner The classical owner address.
    /// @param vaultId The vault identifier.
    /// @return The QuipWallet address, or `address(0)` if none exists.
    function quips(
        address owner,
        bytes32 vaultId
    ) external view returns (address);

    /// @notice Returns the vault ID at a given index for an owner.
    /// @param owner The classical owner address.
    /// @param index The index into the owner's vault ID array.
    /// @return The vault ID at the specified index.
    function vaultIds(
        address owner,
        uint256 index
    ) external view returns (bytes32);

    /// @notice Returns the number of vetted implementation codehashes.
    /// @return The count of entries in the vetted set.
    function getVettedCodeCount() external view returns (uint256);

    /// @notice Returns the codehash at a given index in the vetted set.
    /// @param index The index into the vetted set (insertion order).
    /// @return The codehash at the specified index.
    function getVettedCodeAt(uint256 index) external view returns (bytes32);

    /// @notice Returns the index of a codehash in the vetted set.
    /// @param codehash The codehash to look up.
    /// @return The index in the vetted set, or `type(uint256).max` if not found.
    function getVettedCodeIndex(bytes32 codehash) external view returns (uint256);

    /// @notice Returns the implementation address associated with a vetted codehash.
    /// @param codehash The codehash to look up.
    /// @return walletImplementation The implementation contract address.
    function vettedWalletImpls(bytes32 codehash) external view returns (address walletImplementation);

    /// @notice Returns whether a codehash has been deprecated.
    /// @param codehash The codehash to check.
    /// @return isDeprecated True if the codehash is deprecated.
    function deprecatedImpls(bytes32 codehash) external view returns (bool isDeprecated);

    /// @notice Returns the most recently vetted active implementation address.
    /// @return The latest active wallet implementation address, or `address(0)` if none.
    function latestWalletImpl() external view returns (address);
}
