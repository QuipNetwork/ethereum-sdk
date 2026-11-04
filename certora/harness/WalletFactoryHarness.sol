// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

import { WalletFactory } from "../../contracts/WalletFactory.sol";

/// @title WalletFactoryHarness
/// @notice Certora verification harness for `WalletFactory`.
/// @dev The implementation constructor runs `_disableInitializers()`, so the
///      `initializer`-gated `initialize()` entrypoint can never succeed on the
///      implementation itself. The harness therefore seeds the owner directly
///      through Solady's internal `_initializeOwner` (legal here: the ERC-7201
///      owner slot is still empty after construction, and the harness is never
///      deployed on-chain). This reproduces the post-`initialize` proxy state
///      so CVL rules quantify over realistic factory states.
contract WalletFactoryHarness is WalletFactory {
    constructor(
        uint256 maxFee_,
        address initialOwner
    ) WalletFactory(maxFee_) {
        if (initialOwner == address(0)) revert ZeroAddressOwner();
        _initializeOwner(initialOwner);
    }

    /// @dev Exposes `extcodehash` to CVL specs (CVL has no direct expression
    ///      for it; only an EXTCODEHASH hook opcode).
    function codehashOf(
        address target
    ) external view returns (bytes32) {
        return target.codehash;
    }
}
