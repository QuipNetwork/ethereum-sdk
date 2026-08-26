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

import {Ownable} from "solady-0.1.26/src/auth/Ownable.sol";
import {IPreQSalt1Wallets} from "./interfaces/IPreQSalt1Wallets.sol";

/// @title PreQSalt1Wallets
/// @notice Owner-curated whitelist of pre-QSalt1 (legacy) SHRINCS wallet identities.
contract PreQSalt1Wallets is IPreQSalt1Wallets, Ownable {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         STORAGE                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev One whitelist row. Existence is `owner != address(0)`.
    struct Entry {
        address owner;
        bytes32 statefulC;
        bytes32 statelessC;
    }

    mapping(bytes32 id => Entry) private _entries;

    /// @dev Reverts `ZeroOwner` on a zero `initialOwner`: Solady would otherwise
    ///      store a zero owner and permanently lock every `onlyOwner` entrypoint.
    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert ZeroOwner();
        _initializeOwner(initialOwner);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   INTERNAL OVERRIDES                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Guard owner initialization to prevent re-initialization. This
    ///      contract inherits Solady `Ownable` directly, so it MUST override
    ///      `_guardInitializeOwner => true` itself: `_initializeOwner` then
    ///      reverts `AlreadyInitialized` on a second call.
    function _guardInitializeOwner() internal pure override returns (bool) {
        return true;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   EXTERNAL FUNCTIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @inheritdoc IPreQSalt1Wallets
    function add(
        bytes32 id,
        address owner,
        bytes32 statefulC,
        bytes32 statelessC
    ) external onlyOwner {
        if (owner == address(0)) revert ZeroOwner();
        _entries[id] = Entry({
            owner: owner,
            statefulC: statefulC,
            statelessC: statelessC
        });
        emit Whitelisted(id, owner, statefulC, statelessC);
    }

    /// @inheritdoc IPreQSalt1Wallets
    function remove(bytes32 id) external onlyOwner {
        if (_entries[id].owner == address(0)) revert NotWhitelisted();
        delete _entries[id];
        emit Unwhitelisted(id);
    }

    /// @inheritdoc IPreQSalt1Wallets
    function get(
        bytes32 id
    )
        external
        view
        returns (address owner, bytes32 statefulC, bytes32 statelessC)
    {
        Entry storage e = _entries[id];
        return (e.owner, e.statefulC, e.statelessC);
    }

    /// @inheritdoc IPreQSalt1Wallets
    function isWhitelisted(bytes32 id) external view returns (bool) {
        return _entries[id].owner != address(0);
    }
}
