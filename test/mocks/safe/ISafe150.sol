// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

/// @title ISafe150
/// @dev Minimal Safe{Wallet} v1.5.0 surface the integration tests drive (singleton via proxy).
interface ISafe150 {
    function setup(
        address[] calldata owners,
        uint256 threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    ) external;

    function execTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) external payable returns (bool);

    function checkSignatures(address executor, bytes32 dataHash, bytes calldata signatures) external view;

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce
    ) external view returns (bytes32);

    function nonce() external view returns (uint256);

    function getOwners() external view returns (address[] memory);

    function getThreshold() external view returns (uint256);
}

/// @dev Safe v1.5.0 `SafeProxyFactory`.
interface ISafeProxyFactory150 {
    function createProxyWithNonce(address singleton, bytes calldata initializer, uint256 saltNonce)
        external
        returns (address proxy);
}

/// @dev Safe v1.5.0 `CompatibilityFallbackHandler` (reached through the Safe's fallback).
interface ICompatibilityFallbackHandler150 {
    function isValidSignature(bytes32 dataHash, bytes calldata signature) external view returns (bytes4);

    function getMessageHashForSafe(address safe, bytes calldata message) external view returns (bytes32);
}
