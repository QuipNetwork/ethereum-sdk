// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @notice Contract that always reverts on native receipt or explicit revert calls.
contract DummyQuipRevertingReceiver {
    error DummyQuipForcedRevert();

    receive() external payable {
        revert DummyQuipForcedRevert();
    }

    fallback() external payable {
        revert DummyQuipForcedRevert();
    }

    function alwaysRevert() external pure {
        revert DummyQuipForcedRevert();
    }
}
