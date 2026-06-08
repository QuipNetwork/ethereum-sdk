// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {ERC721} from "@openzeppelin-contracts-5.6.0-rc.1/token/ERC721/ERC721.sol";
import {ERC721Burnable} from
    "@openzeppelin-contracts-5.6.0-rc.1/token/ERC721/extensions/ERC721Burnable.sol";

/// @title DummyQuipERC721
/// @notice Test-only ERC-721 built on OpenZeppelin for Quip QA / testnet flows.
/// @dev Exposes a parameter-free `mint(to)` that auto-allocates the next sequential
///      token id; callers never have to pick or coordinate ids. Returns the minted
///      id so the caller learns it from the call return. Burnable via
///      ERC721Burnable. Tracks `totalSupply`. Not for production.
contract DummyQuipERC721 is ERC721, ERC721Burnable {
    /// @notice Monotonic counter; equals the id that the next `mint` call will assign.
    uint256 public nextTokenId;
    /// @notice Live total supply (incremented on mint, decremented on burn).
    uint256 public totalSupply;

    constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {}

    /// @notice Mint exactly one NFT to `to`. Caller does not pick the id.
    /// @param to Recipient (EOA or contract — `_safeMint` enforces ERC721 receiver hook).
    /// @return tokenId Id assigned to the newly minted token (equal to the pre-call
    ///                 value of `nextTokenId`).
    function mint(address to) external returns (uint256 tokenId) {
        tokenId = nextTokenId;
        _safeMint(to, tokenId);
        unchecked {
            nextTokenId += 1;
        }
    }

    /// @dev Track `totalSupply` via the unified `_update` hook.
    ///      Increments on mint, decrements on burn, no-op on transfer.
    function _update(address to, uint256 tokenId, address auth)
        internal
        override
        returns (address from)
    {
        from = super._update(to, tokenId, auth);
        if (from == address(0) && to != address(0)) {
            unchecked {
                totalSupply += 1;
            }
        } else if (to == address(0) && from != address(0)) {
            unchecked {
                totalSupply -= 1;
            }
        }
    }
}
