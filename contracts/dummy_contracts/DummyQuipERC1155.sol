// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {ERC1155} from "@openzeppelin-contracts-5.6.0-rc.1/token/ERC1155/ERC1155.sol";
import {ERC1155Burnable} from
    "@openzeppelin-contracts-5.6.0-rc.1/token/ERC1155/extensions/ERC1155Burnable.sol";
import {ERC1155Supply} from
    "@openzeppelin-contracts-5.6.0-rc.1/token/ERC1155/extensions/ERC1155Supply.sol";

/// @title DummyQuipERC1155
/// @notice Test-only ERC-1155 built on OpenZeppelin for Quip QA / testnet flows.
/// @dev Constrains the universe of tokens to exactly two ids — `TOKEN_ID_ONE` (1)
///      and `TOKEN_ID_TWO` (2). Mints go through `mintOne` / `mintTwo`; there is
///      no generic `mint(id, amount)` entrypoint, so the closed set is enforced
///      structurally (you can't typo your way into id=3). Burnable via
///      ERC1155Burnable and supply-tracked via ERC1155Supply. Not for production.
contract DummyQuipERC1155 is ERC1155, ERC1155Burnable, ERC1155Supply {
    /// @notice Canonical id for token type one.
    uint256 public constant TOKEN_ID_ONE = 1;
    /// @notice Canonical id for token type two.
    uint256 public constant TOKEN_ID_TWO = 2;

    constructor(string memory uri_) ERC1155(uri_) {}

    /// @notice Mint `amount` of token type 1 to `to`. Ungated.
    function mintOne(address to, uint256 amount) external {
        _mint(to, TOKEN_ID_ONE, amount, "");
    }

    /// @notice Mint `amount` of token type 2 to `to`. Ungated.
    function mintTwo(address to, uint256 amount) external {
        _mint(to, TOKEN_ID_TWO, amount, "");
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
