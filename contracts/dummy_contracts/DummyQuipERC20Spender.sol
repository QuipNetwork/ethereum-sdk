// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface IDummyQuipERC20Like {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
}

/// @notice Pulls ERC-20 tokens via transferFrom for approval/allowance testing.
/// @dev Functions are intentionally nonpayable. Any accidental native value causes a revert.
contract DummyQuipERC20Spender {
    event DummyQuipPulled(
        address indexed token,
        address indexed from,
        address indexed to,
        uint256 amount,
        address caller
    );

    error DummyQuipERC20TransferFromFailed();

    function pull(address token, address from, address to, uint256 amount) external {
        bool ok = IDummyQuipERC20Like(token).transferFrom(from, to, amount);
        if (!ok) revert DummyQuipERC20TransferFromFailed();
        emit DummyQuipPulled(token, from, to, amount, msg.sender);
    }

    function pullToSelf(address token, address from, uint256 amount) external {
        bool ok = IDummyQuipERC20Like(token).transferFrom(from, address(this), amount);
        if (!ok) revert DummyQuipERC20TransferFromFailed();
        emit DummyQuipPulled(token, from, address(this), amount, msg.sender);
    }

    function allowanceOf(address token, address tokenOwner) external view returns (uint256) {
        return IDummyQuipERC20Like(token).allowance(tokenOwner, address(this));
    }

    function tokenBalance(address token, address account) external view returns (uint256) {
        return IDummyQuipERC20Like(token).balanceOf(account);
    }
}
