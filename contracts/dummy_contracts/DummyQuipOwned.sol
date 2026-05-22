// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Tiny owner helper for test-only contracts. Not intended as production access control.
abstract contract DummyQuipOwned {
    address public owner;

    event DummyQuipOwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error DummyQuipNotOwner(address caller);
    error DummyQuipZeroOwner();

    modifier onlyOwner() {
        if (msg.sender != owner) revert DummyQuipNotOwner(msg.sender);
        _;
    }

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert DummyQuipZeroOwner();
        owner = initialOwner;
        emit DummyQuipOwnershipTransferred(address(0), initialOwner);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert DummyQuipZeroOwner();
        address previousOwner = owner;
        owner = newOwner;
        emit DummyQuipOwnershipTransferred(previousOwner, newOwner);
    }
}
