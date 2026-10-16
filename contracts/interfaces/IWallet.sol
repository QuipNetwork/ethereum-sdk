// Copyright (C) 2025 quip.network
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.33;

/// @title IWallet
/// @notice The minimal factory-facing surface of a Quip wallet implementation.
///         The factory is agnostic to the signature scheme securing the wallet
///         (WOTS+, SHRINCS, or future families); it interacts with every wallet
///         exclusively through this interface.
///
/// @dev THE VETTING CONTRACT. `WalletFactory.vetImplementation` is the trust
///      boundary for everything the factory cannot enforce in code. The
///      registry-consistency argument in `updateWalletOwner` (invariant: a
///      wallet's `walletOwner` entry always equals its live `owner()`) rests
///      on every vetted implementation upholding ALL of the following:
///
///        1. `initialize` is callable only by the deploying factory
///           (`msg.sender == FACTORY`) and only once (initializer guard).
///        2. `owner()` mutates ONLY inside the wallet's PQ-authenticated
///           ownership-transfer flow, whose tail calls back into the
///           factory's `updateWalletOwner(newOwner)` in the same
///           transaction, AFTER the new owner is committed. No other path —
///           including arbitrary-call, delegatecall, or raw-storage-write
///           entry points — may reach a state where `owner()` changed
///           without that callback.
///        3. The classical (non-PQ) ownership entry points inherited from
///           the implementation's ownable base are disabled, so `owner()`
///           cannot be moved without post-quantum authorization.
///        4. `verifyUpgrade` reads no storage; `migrate` never clears a
///           consumed leaf/key marker (used-leaf bit, spent-tree entry)
///           for state it leaves live.
///        5. `upgradeToAndCall` forwards the auth blob's opaque
///           `probePayload` / `migratorPayload` UNPARSED to the new
///           implementation's `verifyUpgrade` / `migrate`.
///
///      A vetted implementation that violates these rules can desync the
///      factory's per-owner registry (`walletOwner` / `commitments`); it
///      cannot corrupt other wallets or the vetted set itself.
interface IWallet {
    /// @notice Initializes a freshly deployed wallet proxy.
    /// @dev Called by the factory exactly once, immediately after CREATE3
    ///      deployment and before any ETH is forwarded. The payload is
    ///      implementation-defined and completely opaque to the factory:
    ///      each wallet family documents and validates its own layout
    ///      (length included) in its own codec.
    /// @param newOwner The classical address that will own the new wallet.
    /// @param payload Implementation-defined init data.
    function initialize(
        address payable newOwner,
        bytes calldata payload
    ) external;

    /// @notice Returns the wallet's current classical owner.
    /// @dev Read by the factory's `updateWalletOwner` callback to pin the
    ///      callback to the tail of the wallet's ownership-transfer flow
    ///      (vetting-contract rule 2). Exposed here so the factory does not
    ///      depend on any particular ownable base's types.
    function owner() external view returns (address);

    /// @notice A PROBE — context-free self-test of an implementation's signature scheme,
    ///         never an authorization.
    /// @dev Frozen upgrade seam (with `migrate`): STATICCALLed on the NEW implementation by
    ///      the previous one's `upgradeToAndCall`, forwarding the auth blob's opaque probe
    ///      vector. The vector is scheme-defined (throwaway key + signature(s) binding
    ///      `newImplementation`); the probe needs no wallet state. Verifies → return; else
    ///      revert. The selector matches the deployed implementations and may never change.
    /// @param newImplementation The upgrade target (== the callee); bound into the digest.
    /// @param data Scheme-defined probe vector, opaque to the caller.
    function verifyUpgrade(
        address newImplementation,
        bytes calldata data
    ) external view;

    /// @notice Re-installs the wallet's PQ state during an upgrade.
    /// @dev Second half of the frozen seam: delegatecalled by the previous
    ///      implementation's `upgradeToAndCall`. Layout is defined and validated by the
    ///      NEW family's codec; vetting rule 4 gates its writes. `migrate` gates itself on
    ///      the wallet's OWN implementation pointer (ERC-1967): callable only while the
    ///      installed implementation is a DIFFERENT, nonzero address — i.e. mid-upgrade.
    /// @param payload Scheme-defined migration data, opaque to the caller.
    function migrate(bytes calldata payload) external;
}
