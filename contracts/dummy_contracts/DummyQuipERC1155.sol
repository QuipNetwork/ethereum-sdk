// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {DummyQuipOwned} from "./DummyQuipOwned.sol";

interface IDummyQuipERC1155Receiver {
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4);
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4);
}

/// @notice Minimal ERC-1155 for Quip QA/testnet flows.
/// @dev This is deliberately simple and test-only. Do not use as a production multi-token.
contract DummyQuipERC1155 is DummyQuipOwned {
    string public uri;

    bool public faucetEnabled;
    uint256 public faucetCap;

    mapping(uint256 id => mapping(address account => uint256 balance)) public balanceOf;
    mapping(address account => mapping(address operator => bool approved)) public isApprovedForAll;

    event TransferSingle(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256 id,
        uint256 value
    );
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] values
    );
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);
    event URI(string value, uint256 indexed id);

    event DummyQuipFaucetConfigured(bool enabled, uint256 cap);
    event DummyQuipFaucetMint(
        address indexed caller, address indexed to, uint256 indexed id, uint256 amount
    );
    event DummyQuipURIChanged(string newUri);

    error DummyQuipZeroAddress();
    error DummyQuipNotOwnerOrApproved(address caller, address account);
    error DummyQuipInsufficientBalance(
        address account, uint256 id, uint256 balance, uint256 amount
    );
    error DummyQuipFaucetDisabled();
    error DummyQuipFaucetCapExceeded(uint256 amount, uint256 cap);
    error DummyQuipZeroAmount();
    error DummyQuipLengthMismatch(uint256 idsLength, uint256 amountsLength);
    error DummyQuipUnsafeRecipient(address to);

    constructor(string memory uri_, address initialOwner, bool faucetEnabled_, uint256 faucetCap_)
        DummyQuipOwned(initialOwner)
    {
        uri = uri_;
        faucetEnabled = faucetEnabled_;
        faucetCap = faucetCap_;
        emit DummyQuipFaucetConfigured(faucetEnabled_, faucetCap_);
    }

    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids)
        external
        view
        returns (uint256[] memory balances)
    {
        if (accounts.length != ids.length) {
            revert DummyQuipLengthMismatch(ids.length, accounts.length);
        }
        balances = new uint256[](accounts.length);
        for (uint256 i = 0; i < accounts.length; ++i) {
            balances[i] = balanceOf[ids[i]][accounts[i]];
        }
    }

    function setApprovalForAll(address operator, bool approved) external {
        isApprovedForAll[msg.sender][operator] = approved;
        emit ApprovalForAll(msg.sender, operator, approved);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external {
        if (msg.sender != from && !isApprovedForAll[from][msg.sender]) {
            revert DummyQuipNotOwnerOrApproved(msg.sender, from);
        }
        _transfer(from, to, id, amount);
        emit TransferSingle(msg.sender, from, to, id, amount);
        _checkOnERC1155Received(from, to, id, amount, data);
    }

    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external {
        if (ids.length != amounts.length) {
            revert DummyQuipLengthMismatch(ids.length, amounts.length);
        }
        if (msg.sender != from && !isApprovedForAll[from][msg.sender]) {
            revert DummyQuipNotOwnerOrApproved(msg.sender, from);
        }
        for (uint256 i = 0; i < ids.length; ++i) {
            _transfer(from, to, ids[i], amounts[i]);
        }
        emit TransferBatch(msg.sender, from, to, ids, amounts);
        _checkOnERC1155BatchReceived(from, to, ids, amounts, data);
    }

    /// @notice Public testnet faucet. Owner can disable it or change the cap.
    function faucet(address to, uint256 id, uint256 amount) external {
        if (!faucetEnabled) revert DummyQuipFaucetDisabled();
        if (amount == 0) revert DummyQuipZeroAmount();
        if (amount > faucetCap) revert DummyQuipFaucetCapExceeded(amount, faucetCap);
        _mint(to, id, amount);
        emit DummyQuipFaucetMint(msg.sender, to, id, amount);
    }

    /// @notice Ungated test mint. Anyone can mint any amount.
    function mint(address to, uint256 id, uint256 amount) external {
        if (amount == 0) revert DummyQuipZeroAmount();
        _mint(to, id, amount);
    }

    /// @notice Owner-only mint path for private-faucet or demo-control mode.
    function ownerMint(address to, uint256 id, uint256 amount) external onlyOwner {
        if (amount == 0) revert DummyQuipZeroAmount();
        _mint(to, id, amount);
    }

    /// @notice Burn `from` balance using approval (or own balance when `from` is caller).
    function burn(address from, uint256 id, uint256 amount) external {
        if (msg.sender != from && !isApprovedForAll[from][msg.sender]) {
            revert DummyQuipNotOwnerOrApproved(msg.sender, from);
        }
        if (amount == 0) revert DummyQuipZeroAmount();
        uint256 fromBalance = balanceOf[id][from];
        if (fromBalance < amount) {
            revert DummyQuipInsufficientBalance(from, id, fromBalance, amount);
        }
        unchecked {
            balanceOf[id][from] = fromBalance - amount;
        }
        emit TransferSingle(msg.sender, from, address(0), id, amount);
    }

    function setURI(string calldata newUri) external onlyOwner {
        uri = newUri;
        emit DummyQuipURIChanged(newUri);
    }

    function setFaucetConfig(bool enabled, uint256 cap) external onlyOwner {
        faucetEnabled = enabled;
        faucetCap = cap;
        emit DummyQuipFaucetConfigured(enabled, cap);
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0xd9b67a26 // ERC-1155
            || interfaceId == 0x0e89341c // ERC-1155 MetadataURI
            || interfaceId == 0x01ffc9a7; // ERC-165
    }

    function _mint(address to, uint256 id, uint256 amount) internal {
        if (to == address(0)) revert DummyQuipZeroAddress();
        balanceOf[id][to] += amount;
        emit TransferSingle(msg.sender, address(0), to, id, amount);
    }

    function _transfer(address from, address to, uint256 id, uint256 amount) internal {
        if (to == address(0)) revert DummyQuipZeroAddress();
        uint256 fromBalance = balanceOf[id][from];
        if (fromBalance < amount) {
            revert DummyQuipInsufficientBalance(from, id, fromBalance, amount);
        }
        unchecked {
            balanceOf[id][from] = fromBalance - amount;
            balanceOf[id][to] += amount;
        }
    }

    function _checkOnERC1155Received(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) internal {
        if (to.code.length == 0) return;
        try IDummyQuipERC1155Receiver(to).onERC1155Received(msg.sender, from, id, amount, data)
            returns (bytes4 retval)
        {
            if (retval != IDummyQuipERC1155Receiver.onERC1155Received.selector) {
                revert DummyQuipUnsafeRecipient(to);
            }
        } catch {
            revert DummyQuipUnsafeRecipient(to);
        }
    }

    function _checkOnERC1155BatchReceived(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) internal {
        if (to.code.length == 0) return;
        try IDummyQuipERC1155Receiver(to).onERC1155BatchReceived(
            msg.sender, from, ids, amounts, data
        ) returns (bytes4 retval) {
            if (retval != IDummyQuipERC1155Receiver.onERC1155BatchReceived.selector) {
                revert DummyQuipUnsafeRecipient(to);
            }
        } catch {
            revert DummyQuipUnsafeRecipient(to);
        }
    }
}
