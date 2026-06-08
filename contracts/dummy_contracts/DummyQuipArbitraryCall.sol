// SPDX-License-Identifier: MIT
pragma solidity ^0.8.33;

/// @title DummyQuipArbitraryCall
/// @notice Stupid-simple test target for exercising the Quip Wallet's
///         arbitrary-call path. Two functions, zero arguments:
///           - `ping()`         → success path. Bumps `pingCountOf[msg.sender]`.
///           - `alwaysRevert()` → revert path. Reverts with `AlwaysReverts()`.
///         Identity is keyed on `msg.sender`, NOT `tx.origin`, so when called
///         via a smart wallet the counter accumulates under the WALLET's
///         address (consistent with how token balances behave). Not for prod.
contract DummyQuipArbitraryCall {
    /// @notice Sole custom error this contract ever reverts with. Tests can
    ///         match the 4-byte selector exactly to verify revert propagation.
    error AlwaysReverts();

    /// @notice Per-`msg.sender` call counter. The only state this contract
    ///         keeps. Read by the frontend as the user's "you've pinged N
    ///         times" display.
    mapping(address => uint256) public pingCountOf;

    /// @notice Bumps the caller's per-address counter. Ungated, no args,
    ///         no value, no return — just an increment.
    function ping() external {
        unchecked {
            pingCountOf[msg.sender] += 1;
        }
    }

    /// @notice Always reverts with `AlwaysReverts()`. Pure — no state, no
    ///         args, no fluff.
    function alwaysRevert() external pure {
        revert AlwaysReverts();
    }
}
