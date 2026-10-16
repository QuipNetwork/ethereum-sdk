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

// prettier-ignore
import {EnumerableWinternitzAddressSet as Keyset} from "./EnumerableWinternitzAddressSet.sol";
import {WOTSPlus} from "@quip.network/hashsigs-solidity-0.2.0/contracts/WOTSPlus.sol";

/// @custom:deprecated The WOTS+ wallet family is sunset — superseded by SHRINCS
///                    (contracts/shrincs/). Kept fully functional for existing deployments.
library WOTSPlusStorage {
    /// @custom:storage-location erc7201:quip.storage.wallet.wotsplus
    struct Layout {
        /// @dev Set once during `initialize`; effectively immutable after deployment.
        address payable quipFactory;
        /// @dev Single Winternitz public key that authorizes `saveWallet` — the last-resort
        ///      rescue that resets `transactionKeys` and `recoveryKeys` when both sets have
        ///      been compromised or corrupted. Rotates on use (WOTS+ one-time-use). Occupies
        ///      two storage slots (publicSeed + publicKeyHash); both are guarded unconditionally
        ///      by `storageStoreGuard` and snapshotted by `delegateExecuteGuard`. Placed ahead
        ///      of the three keysets so its slot offsets are fixed across future layout changes.
        WOTSPlus.WinternitzAddress disasterRecoveryKey;
        /// @dev Single Winternitz public key that authorizes `transferOwnership` and
        ///      `completeOwnershipHandover` — the ownership-transfer backstop. Rotates on use
        ///      (WOTS+ one-time-use). Occupies two storage slots (publicSeed + publicKeyHash);
        ///      both are guarded unconditionally by `storageStoreGuard` and snapshotted by
        ///      `delegateExecuteGuard` so a malicious delegate cannot replace it. Separated
        ///      from `transactionKeys` so ownership transfer survives transaction-keyset
        ///      corruption and vice versa.
        WOTSPlus.WinternitzAddress ownershipKey;
        /// @dev Enumerable set of Winternitz public keys authorized to sign guarded
        ///      transactions. Each op names a (currentKey, nextKey) pair; on success the
        ///      current key is consumed and the next is installed, preserving WOTS+
        ///      one-time-use while permitting parallel outstanding signatures.
        Keyset.WinternitzAddressSet transactionKeys;
        /// @dev Enumerable set of Winternitz public keys authorized to recover the wallet or
        ///      authorize an emergency implementation upgrade. Consumed one-time on use.
        ///      Capacity: `MAX_KEYS`.
        Keyset.WinternitzAddressSet recoveryKeys;
        /// @dev Enumerable set of Winternitz public keys authorized to sign ERC-1271 messages.
        ///      Managed post-init via transaction-key-authenticated calls. Capacity: `MAX_KEYS`.
        Keyset.WinternitzAddressSet verificationKeys;
        /// @dev Monotonic burn index for every WOTS+ key this wallet has ever installed in
        ///      any slot (keysets or singles). Keyed by `hash(publicSeed, publicKeyHash)`.
        ///      Set on install, NEVER cleared on removal — WOTS+ is a one-time signature
        ///      scheme, so any key that has appeared in a live slot must be assumed to have
        ///      its chain material revealed and can never be re-installed. Mirrors the
        ///      paymaster's `verifierKeyUsed` index for parity across the system.
        mapping(bytes32 keyHash => bool spent) isKeySpent;
    }

    /// @dev `keccak256(abi.encode(uint256(keccak256("quip.storage.wallet.wotsplus")) - 1))
    ///      & ~bytes32(uint256(0xff))`.
    ///      Single source of truth for the ERC-7201 namespace base. All
    ///      derived per-field constants below are aliased into
    ///      `WOTSPlusImplementation`'s `storageStoreGuard` / `delegateExecuteGuard` so
    ///      the wallet's pre/post-snapshot Yul checks read from the same
    ///      slots the library's `layout()` writes to. Solidity's inline
    ///      assembly only accepts direct numeric constants (or references
    ///      to them), which is why each derived offset is its own hex
    ///      literal here rather than `base + N`.
    bytes32 internal constant _WOTSPLUS_STORAGE_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;

    /// @dev Slots of the first five `Layout` fields that `WOTSPlusImplementation`'s
    ///      guard modifiers snapshot/check. Must be kept in lock-step with
    ///      the field order of `Layout` above;
    ///      `test/deprecated/fixtures/WOTSPlusImplementation.storageLayout.json`
    ///      pins each field's slot offset and fails the suite on any drift.
    ///      A namespace rename above must regenerate every literal below
    ///      together — they aren't independently meaningful.
    bytes32 internal constant _PQ_FACTORY_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf700;
    bytes32 internal constant _DISASTER_KEY_SEED_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf701;
    bytes32 internal constant _DISASTER_KEY_HASH_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf702;
    bytes32 internal constant _OWNERSHIP_KEY_SEED_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf703;
    bytes32 internal constant _OWNERSHIP_KEY_HASH_SLOT =
        0xd236c5053dd0f156c8b3373802638cbeb13d4fb4daee39c2ecb72bad342cf704;

    /// @dev Returns the ERC-7201 namespaced storage layout.
    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := _WOTSPLUS_STORAGE_SLOT
        }
    }
}
