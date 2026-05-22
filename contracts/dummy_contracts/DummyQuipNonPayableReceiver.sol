// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Contract with no receive/fallback. Native transfers to it should fail.
contract DummyQuipNonPayableReceiver {
    event DummyQuipPing(address indexed caller);

    function ping() external {
        emit DummyQuipPing(msg.sender);
    }
}
