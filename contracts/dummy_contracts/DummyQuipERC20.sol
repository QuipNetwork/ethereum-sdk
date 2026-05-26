// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {DummyQuipOwned} from "./DummyQuipOwned.sol";

/// @notice Minimal ERC-20 for Quip QA/testnet flows.
/// @dev This is deliberately simple and test-only. Do not use as a production token.
contract DummyQuipERC20 is DummyQuipOwned {
    string public name;
    string public symbol;
    uint8 public immutable decimals;

    uint256 public totalSupply;
    bool public faucetEnabled;
    uint256 public faucetCap;

    mapping(address account => uint256 balance) public balanceOf;
    mapping(address owner => mapping(address spender => uint256 allowance)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event DummyQuipFaucetConfigured(bool enabled, uint256 cap);
    event DummyQuipFaucetMint(address indexed caller, address indexed to, uint256 amount);

    error DummyQuipZeroAddress();
    error DummyQuipInsufficientBalance(address account, uint256 balance, uint256 amount);
    error DummyQuipInsufficientAllowance(address owner, address spender, uint256 allowance, uint256 amount);
    error DummyQuipFaucetDisabled();
    error DummyQuipFaucetCapExceeded(uint256 amount, uint256 cap);
    error DummyQuipZeroAmount();

    constructor(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address initialOwner,
        bool faucetEnabled_,
        uint256 faucetCap_
    ) DummyQuipOwned(initialOwner) {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        faucetEnabled = faucetEnabled_;
        faucetCap = faucetCap_;
        emit DummyQuipFaucetConfigured(faucetEnabled_, faucetCap_);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 currentAllowance = allowance[from][msg.sender];
        if (currentAllowance != type(uint256).max) {
            if (currentAllowance < amount) {
                revert DummyQuipInsufficientAllowance(from, msg.sender, currentAllowance, amount);
            }
            unchecked {
                _approve(from, msg.sender, currentAllowance - amount);
            }
        }

        _transfer(from, to, amount);
        return true;
    }

    /// @notice Public testnet faucet. Owner can disable it or change the cap.
    function faucet(address to, uint256 amount) external {
        if (!faucetEnabled) revert DummyQuipFaucetDisabled();
        if (amount == 0) revert DummyQuipZeroAmount();
        if (amount > faucetCap) revert DummyQuipFaucetCapExceeded(amount, faucetCap);
        _mint(to, amount);
        emit DummyQuipFaucetMint(msg.sender, to, amount);
    }

    /// @notice Ungated test mint. Anyone can mint any amount.
    function mint(address to, uint256 amount) external {
        if (amount == 0) revert DummyQuipZeroAmount();
        _mint(to, amount);
    }

    /// @notice Burn caller balance.
    function burn(uint256 amount) external {
        _burn(msg.sender, amount);
    }

    /// @notice Burn `from` balance using allowance (or own balance when `from` is caller).
    function burnFrom(address from, uint256 amount) external {
        if (from != msg.sender) {
            uint256 currentAllowance = allowance[from][msg.sender];
            if (currentAllowance != type(uint256).max) {
                if (currentAllowance < amount) {
                    revert DummyQuipInsufficientAllowance(from, msg.sender, currentAllowance, amount);
                }
                unchecked {
                    _approve(from, msg.sender, currentAllowance - amount);
                }
            }
        }
        _burn(from, amount);
    }

    /// @notice Owner-only mint path for private-faucet or demo-control mode.
    function ownerMint(address to, uint256 amount) external onlyOwner {
        if (amount == 0) revert DummyQuipZeroAmount();
        _mint(to, amount);
    }

    function setFaucetConfig(bool enabled, uint256 cap) external onlyOwner {
        faucetEnabled = enabled;
        faucetCap = cap;
        emit DummyQuipFaucetConfigured(enabled, cap);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        if (to == address(0)) revert DummyQuipZeroAddress();
        uint256 fromBalance = balanceOf[from];
        if (fromBalance < amount) revert DummyQuipInsufficientBalance(from, fromBalance, amount);

        unchecked {
            balanceOf[from] = fromBalance - amount;
            balanceOf[to] += amount;
        }

        emit Transfer(from, to, amount);
    }

    function _approve(address owner_, address spender, uint256 amount) internal {
        if (owner_ == address(0) || spender == address(0)) revert DummyQuipZeroAddress();
        allowance[owner_][spender] = amount;
        emit Approval(owner_, spender, amount);
    }

    function _mint(address to, uint256 amount) internal {
        if (to == address(0)) revert DummyQuipZeroAddress();
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        if (amount == 0) revert DummyQuipZeroAmount();
        uint256 fromBalance = balanceOf[from];
        if (fromBalance < amount) revert DummyQuipInsufficientBalance(from, fromBalance, amount);

        unchecked {
            balanceOf[from] = fromBalance - amount;
            totalSupply -= amount;
        }

        emit Transfer(from, address(0), amount);
    }
}
