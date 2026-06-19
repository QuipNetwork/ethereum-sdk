// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

/// @dev Minimal stand-in for QuipFactory exposing only the surface `ShrincsWallet` calls:
///      `executeFee`, `getVettedCodeIndex`, `deprecatedImpls`, and `updateWalletOwner`.
contract MockShrincsFactory {
    uint256 public executeFee;
    mapping(bytes32 codehash => uint256 index) internal _vettedIndex;
    mapping(bytes32 codehash => bool deprecated) public deprecatedImpls;
    mapping(address wallet => address owner) public lastOwnerUpdate;

    function setExecuteFee(uint256 fee) external {
        executeFee = fee;
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

    /// @dev Records the callback; mirrors QuipFactory's `owner() == newOwner` pin loosely.
    function updateWalletOwner(address newOwner) external {
        lastOwnerUpdate[msg.sender] = newOwner;
    }

    receive() external payable {}
}
