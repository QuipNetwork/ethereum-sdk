// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

/// @dev Trivial sink so the sponsored contract-call e2e can prove the wallet actually invoked a
///      target with the expected caller/value/calldata.
contract MockCallTarget {
    address public lastCaller;
    uint256 public lastValue;
    bytes public lastData;
    uint256 public callCount;

    fallback() external payable {
        lastCaller = msg.sender;
        lastValue = msg.value;
        lastData = msg.data;
        callCount += 1;
    }

    receive() external payable {
        lastCaller = msg.sender;
        lastValue = msg.value;
        callCount += 1;
    }
}
