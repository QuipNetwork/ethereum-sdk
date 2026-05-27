// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {ERC1155} from "@openzeppelin-contracts-5.6.0-rc.1/token/ERC1155/ERC1155.sol";
import {ERC1155Burnable} from
    "@openzeppelin-contracts-5.6.0-rc.1/token/ERC1155/extensions/ERC1155Burnable.sol";
import {ERC1155Supply} from
    "@openzeppelin-contracts-5.6.0-rc.1/token/ERC1155/extensions/ERC1155Supply.sol";

/// @title DummyQuipERC1155
/// @notice Test-only ERC-1155 built on OpenZeppelin for Quip QA / testnet flows.
/// @dev Exposes a single ungated `mint(to, id, amount)` plus burn via ERC1155Burnable
///      and `totalSupply(id)` via ERC1155Supply. URI is set once in the constructor.
///      Not for production.
contract DummyQuipERC1155 is ERC1155, ERC1155Burnable, ERC1155Supply {
    constructor(string memory uri_) ERC1155(uri_) {}

    /// @notice Ungated per-id mint.
    function mint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }

    /// @dev Resolve diamond inheritance between ERC1155 and ERC1155Supply.
    function _update(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory values
    ) internal override(ERC1155, ERC1155Supply) {
        super._update(from, to, ids, values);
    }
}
