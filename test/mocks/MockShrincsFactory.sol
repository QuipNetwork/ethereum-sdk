// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import {IWalletFactory} from "../../contracts/interfaces/IWalletFactory.sol";

/// @dev Minimal stand-in for WalletFactory exposing only the surface `ShrincsWallet` calls:
///      `executeFee`, `getVettedCodeIndex`, `deprecatedImpls`, `updateWalletOwner`, plus the
///      e3r deploy-context getters the wallet's `initialize` reads (`vaultIdOf`,
///      `quipDeployChainIndex`, `deployMode`, `pendingDeployCommitment`).
contract MockShrincsFactory {
    uint256 public executeFee;
    mapping(bytes32 codehash => uint256 index) internal _vettedIndex;
    mapping(bytes32 codehash => bool deprecated) public deprecatedImpls;
    mapping(address wallet => address owner) public lastOwnerUpdate;

    // --- e3r deploy config (settable by tests) ---
    mapping(address wallet => bytes32 vaultId) public vaultIdOf;
    uint16 public quipDeployChainIndex;
    IWalletFactory.DeployMode public deployMode;
    bytes32 public pendingDeployCommitment;

    function setExecuteFee(uint256 fee) external {
        executeFee = fee;
    }

    /// @dev Configure the deploy context the wallet reads during `initialize`.
    function setDeployContext(
        address wallet,
        bytes32 vaultId,
        uint16 quipDeployChainIndex_,
        IWalletFactory.DeployMode deployMode_,
        bytes32 pendingDeployCommitment_
    ) external {
        vaultIdOf[wallet] = vaultId;
        quipDeployChainIndex = quipDeployChainIndex_;
        deployMode = deployMode_;
        pendingDeployCommitment = pendingDeployCommitment_;
    }

    function vet(bytes32 codehash, uint256 index) external {
        _vettedIndex[codehash] = index + 1; // store 1-based; 0 = not vetted
    }

    function setDeprecated(bytes32 codehash, bool value) external {
        deprecatedImpls[codehash] = value;
    }

    function getVettedCodeIndex(bytes32 codehash) external view returns (uint256) {
        uint256 stored = _vettedIndex[codehash];
        return stored == 0 ? type(uint256).max : stored - 1;
    }

    /// @dev Records the callback; mirrors WalletFactory's `owner() == newOwner` pin loosely.
    function updateWalletOwner(address newOwner) external {
        lastOwnerUpdate[msg.sender] = newOwner;
    }

    receive() external payable {}
}
