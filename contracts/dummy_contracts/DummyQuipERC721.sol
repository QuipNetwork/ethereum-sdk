// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {ERC721} from "@openzeppelin-contracts-5.6.0-rc.1/token/ERC721/ERC721.sol";
import {ERC721Burnable} from
    "@openzeppelin-contracts-5.6.0-rc.1/token/ERC721/extensions/ERC721Burnable.sol";

/// @title DummyQuipERC721
/// @notice Test-only ERC-721 built on OpenZeppelin for Quip QA / testnet flows.
/// @dev Exposes a single ungated `mint(to, amount)` that auto-increments token IDs,
///      plus burn via ERC721Burnable. Tracks `totalSupply`. Not for production.
contract DummyQuipERC721 is ERC721, ERC721Burnable {
    uint256 public nextTokenId;
    uint256 public totalSupply;

    constructor(string memory name_, string memory symbol_) ERC721(name_, symbol_) {}

    /// @notice Ungated mint of `amount` sequential token IDs to `to`.
    function mint(address to, uint256 amount) external {
        for (uint256 i = 0; i < amount; ++i) {
            _safeMint(to, nextTokenId);
            unchecked {
                nextTokenId += 1;
            }
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
