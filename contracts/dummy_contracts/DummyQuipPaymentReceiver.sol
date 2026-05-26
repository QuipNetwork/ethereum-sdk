// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

import {DummyQuipOwned} from "./DummyQuipOwned.sol";

/// @notice Receives native ETH on testnets and emits clear events for SDK/payment QA.
contract DummyQuipPaymentReceiver is DummyQuipOwned {
    event DummyQuipNativeReceived(address indexed sender, uint256 value, uint256 newBalance, bytes data);
    event DummyQuipReferencePayment(address indexed sender, uint256 value, bytes32 indexed referenceId);
    event DummyQuipNativeWithdrawn(address indexed to, uint256 amount);

    error DummyQuipNativeWithdrawFailed();

    constructor(address initialOwner) DummyQuipOwned(initialOwner) {}

    receive() external payable {
        emit DummyQuipNativeReceived(msg.sender, msg.value, address(this).balance, "");
    }

    fallback() external payable {
        emit DummyQuipNativeReceived(msg.sender, msg.value, address(this).balance, msg.data);
    }

    function pay(bytes32 referenceId) external payable {
        emit DummyQuipReferencePayment(msg.sender, msg.value, referenceId);
    }

    function withdrawNative(address payable to, uint256 amount) external onlyOwner {
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert DummyQuipNativeWithdrawFailed();
        emit DummyQuipNativeWithdrawn(to, amount);
    }
}
