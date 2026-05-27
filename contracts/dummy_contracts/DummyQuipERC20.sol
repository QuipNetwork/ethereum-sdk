// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {ERC20} from "@openzeppelin-contracts-5.6.0-rc.1/token/ERC20/ERC20.sol";
import {ERC20Burnable} from
    "@openzeppelin-contracts-5.6.0-rc.1/token/ERC20/extensions/ERC20Burnable.sol";

/// @title DummyQuipERC20
/// @notice Test-only ERC-20 built on OpenZeppelin for Quip QA / testnet flows.
/// @dev Exposes a single ungated `mint(to, amount)` plus burn via ERC20Burnable.
///      Decimals are configurable per deployment. Not for production.
contract DummyQuipERC20 is ERC20, ERC20Burnable {
    uint8 private immutable _DECIMALS;

    constructor(string memory name_, string memory symbol_, uint8 decimals_)
        ERC20(name_, symbol_)
    {
        _DECIMALS = decimals_;
    }

    function decimals() public view override returns (uint8) {
        return _DECIMALS;
    }

    /// @notice Ungated mint. Anyone can mint any amount.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}
