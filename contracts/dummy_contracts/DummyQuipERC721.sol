// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {DummyQuipOwned} from "./DummyQuipOwned.sol";

interface IDummyQuipERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}

/// @notice Minimal ERC-721 for Quip QA/testnet flows.
/// @dev This is deliberately simple and test-only. Do not use as a production NFT.
contract DummyQuipERC721 is DummyQuipOwned {
    string public name;
    string public symbol;

    uint256 public nextTokenId;
    uint256 public totalSupply;

    bool public faucetEnabled;
    uint256 public faucetCap;

    mapping(uint256 tokenId => address tokenOwner) internal _ownerOf;
    mapping(address tokenOwner => uint256 balance) public balanceOf;
    mapping(uint256 tokenId => address approved) internal _tokenApproval;
    mapping(address tokenOwner => mapping(address operator => bool approved))
        public isApprovedForAll;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    event DummyQuipFaucetConfigured(bool enabled, uint256 cap);
    event DummyQuipFaucetMint(
        address indexed caller, address indexed to, uint256 firstTokenId, uint256 amount
    );

    error DummyQuipZeroAddress();
    error DummyQuipNotOwnerOrApproved(address caller, uint256 tokenId);
    error DummyQuipWrongFrom(address expected, address actual);
    error DummyQuipNonexistentToken(uint256 tokenId);
    error DummyQuipFaucetDisabled();
    error DummyQuipFaucetCapExceeded(uint256 amount, uint256 cap);
    error DummyQuipZeroAmount();
    error DummyQuipUnsafeRecipient(address to);

    constructor(
        string memory name_,
        string memory symbol_,
        address initialOwner,
        bool faucetEnabled_,
        uint256 faucetCap_
    ) DummyQuipOwned(initialOwner) {
        name = name_;
        symbol = symbol_;
        faucetEnabled = faucetEnabled_;
        faucetCap = faucetCap_;
        emit DummyQuipFaucetConfigured(faucetEnabled_, faucetCap_);
    }

    function ownerOf(uint256 tokenId) public view returns (address tokenOwner) {
        tokenOwner = _ownerOf[tokenId];
        if (tokenOwner == address(0)) revert DummyQuipNonexistentToken(tokenId);
    }

    function getApproved(uint256 tokenId) external view returns (address) {
        if (_ownerOf[tokenId] == address(0)) revert DummyQuipNonexistentToken(tokenId);
        return _tokenApproval[tokenId];
    }

    function approve(address to, uint256 tokenId) external {
        address tokenOwner = ownerOf(tokenId);
        if (msg.sender != tokenOwner && !isApprovedForAll[tokenOwner][msg.sender]) {
            revert DummyQuipNotOwnerOrApproved(msg.sender, tokenId);
        }
        _tokenApproval[tokenId] = to;
        emit Approval(tokenOwner, to, tokenId);
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function transferFrom(address from, address to, uint256 tokenId) public {
        _transfer(from, to, tokenId);
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) external {
        _transfer(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, "");
    }

    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data)
        external
    {
        _transfer(from, to, tokenId);
        _checkOnERC721Received(from, to, tokenId, data);
    }

    /// @notice Public testnet faucet. Owner can disable it or change the cap.
    function faucet(address to, uint256 amount) external {
        if (!faucetEnabled) revert DummyQuipFaucetDisabled();
        if (amount == 0) revert DummyQuipZeroAmount();
        if (amount > faucetCap) revert DummyQuipFaucetCapExceeded(amount, faucetCap);
        uint256 first = nextTokenId;
        for (uint256 i = 0; i < amount; ++i) {
            _mint(to);
        }
        emit DummyQuipFaucetMint(msg.sender, to, first, amount);
    }

    /// @notice Ungated test mint. Anyone can mint any amount.
    function mint(address to, uint256 amount) external {
        if (amount == 0) revert DummyQuipZeroAmount();
        for (uint256 i = 0; i < amount; ++i) {
            _mint(to);
        }
    }

    /// @notice Owner-only mint path for private-faucet or demo-control mode.
    function ownerMint(address to, uint256 amount) external onlyOwner {
        if (amount == 0) revert DummyQuipZeroAmount();
        for (uint256 i = 0; i < amount; ++i) {
            _mint(to);
        }
    }

    /// @notice Burn caller's token (or one they're approved for).
    function burn(uint256 tokenId) external {
        address tokenOwner = ownerOf(tokenId);
        if (
            msg.sender != tokenOwner && _tokenApproval[tokenId] != msg.sender
                && !isApprovedForAll[tokenOwner][msg.sender]
        ) {
            revert DummyQuipNotOwnerOrApproved(msg.sender, tokenId);
        }
        unchecked {
            balanceOf[tokenOwner] -= 1;
            totalSupply -= 1;
        }
        delete _tokenApproval[tokenId];
        delete _ownerOf[tokenId];
        emit Transfer(tokenOwner, address(0), tokenId);
    }

    function setFaucetConfig(bool enabled, uint256 cap) external onlyOwner {
        faucetEnabled = enabled;
        faucetCap = cap;
        emit DummyQuipFaucetConfigured(enabled, cap);
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x80ac58cd // ERC-721
            || interfaceId == 0x01ffc9a7; // ERC-165
    }

    function _mint(address to) internal {
        if (to == address(0)) revert DummyQuipZeroAddress();
        uint256 tokenId = nextTokenId;
        nextTokenId = tokenId + 1;
        _ownerOf[tokenId] = to;
        unchecked {
            balanceOf[to] += 1;
            totalSupply += 1;
        }
        emit Transfer(address(0), to, tokenId);
    }

    function _transfer(address from, address to, uint256 tokenId) internal {
        if (to == address(0)) revert DummyQuipZeroAddress();
        address tokenOwner = ownerOf(tokenId);
        if (tokenOwner != from) revert DummyQuipWrongFrom(tokenOwner, from);
        if (
            msg.sender != tokenOwner && _tokenApproval[tokenId] != msg.sender
                && !isApprovedForAll[tokenOwner][msg.sender]
        ) {
            revert DummyQuipNotOwnerOrApproved(msg.sender, tokenId);
        }

        delete _tokenApproval[tokenId];
        unchecked {
            balanceOf[from] -= 1;
            balanceOf[to] += 1;
        }
        _ownerOf[tokenId] = to;
        emit Transfer(from, to, tokenId);
    }

    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory data)
        internal
    {
        if (to.code.length == 0) return;
        try IDummyQuipERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, data)
            returns (bytes4 retval)
        {
            if (retval != IDummyQuipERC721Receiver.onERC721Received.selector) {
                revert DummyQuipUnsafeRecipient(to);
            }
        } catch {
            revert DummyQuipUnsafeRecipient(to);
        }
    }
}
