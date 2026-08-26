// Copyright (C) 2026 quip.network
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

/// @title IPreQSalt1Wallets
/// @notice Owner-curated whitelist of pre-QSalt1 (legacy) SHRINCS wallet identities.
/// @dev A later WalletFactory task reads this registry to allow deploying wallets
///      whose CREATE3 salt does not carry the QSalt1 identity prefix. Existence is
///      defined as a non-zero `owner` on the stored entry; `add` therefore rejects
///      a zero owner so `isWhitelisted` stays unambiguous.
interface IPreQSalt1Wallets {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         ERRORS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Thrown when `add` is called with a zero owner.
    error ZeroOwner();
    /// @notice Thrown when `remove` is called for an id that is not whitelisted.
    error NotWhitelisted();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         EVENTS                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Emitted when an id is added or updated on the whitelist.
    /// @param id The legacy wallet identity.
    /// @param owner The classical EOA owner of the legacy wallet.
    /// @param statefulC The stateful key commitment.
    /// @param statelessC The stateless key commitment.
    event Whitelisted(
        bytes32 indexed id,
        address indexed owner,
        bytes32 statefulC,
        bytes32 statelessC
    );

    /// @notice Emitted when an id is removed from the whitelist.
    /// @param id The legacy wallet identity that was removed.
    event Unwhitelisted(bytes32 indexed id);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       FUNCTIONS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @notice Adds or overwrites a whitelist entry for `id`.
    /// @dev Caller must be the contract owner. Reverts `ZeroOwner` if `owner` is
    ///      the zero address. Emits `Whitelisted`.
    /// @param id The legacy wallet identity.
    /// @param owner The classical EOA owner of the legacy wallet. Must be non-zero.
    /// @param statefulC The stateful key commitment.
    /// @param statelessC The stateless key commitment.
    function add(
        bytes32 id,
        address owner,
        bytes32 statefulC,
        bytes32 statelessC
    ) external;

    /// @notice Removes the whitelist entry for `id`.
    /// @dev Caller must be the contract owner. Reverts `NotWhitelisted` if no
    ///      entry exists. Emits `Unwhitelisted`.
    /// @param id The legacy wallet identity to remove.
    function remove(bytes32 id) external;

    /// @notice Returns the stored tuple for `id`.
    /// @dev An absent id returns `(address(0), bytes32(0), bytes32(0))`.
    /// @param id The legacy wallet identity.
    /// @return owner The classical EOA owner, or zero if absent.
    /// @return statefulC The stateful key commitment, or zero if absent.
    /// @return statelessC The stateless key commitment, or zero if absent.
    function get(
        bytes32 id
    )
        external
        view
        returns (address owner, bytes32 statefulC, bytes32 statelessC);

    /// @notice Returns whether `id` has a whitelist entry.
    /// @dev True if and only if the stored owner is non-zero.
    /// @param id The legacy wallet identity.
    /// @return True if `id` is whitelisted.
    function isWhitelisted(bytes32 id) external view returns (bool);
}
