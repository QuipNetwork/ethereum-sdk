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

import {EnumerableSetLib} from "solady-0.1.26/src/utils/EnumerableSetLib.sol";

library WalletFactoryStorage {
    /// @dev The ERC-7201 namespace string (and the `_QUIP_FACTORY_STORAGE_SLOT` constant
    ///      derived from it below) deliberately kept `quip.storage.factory` through the
    ///      QuipFactory→WalletFactory rename — it is a wire identifier baked into the live
    ///      proxy's storage layout. NOT a missed rename.
    /// @custom:storage-location erc7201:quip.storage.factory
    struct Layout {
        /// @dev Fee charged when creating a new wallet proxy. Capped by the
        ///      implementation's immutable `MAX_FEE`.
        uint256 creationFee;
        /// @dev Fee charged on PQ-authenticated wallet operations. Capped by
        ///      the implementation's immutable `MAX_FEE`.
        uint256 executeFee;
        /// @dev Wallet deployed at `vaultId` (a GLOBAL CREATE3 salt — the
        ///      address is a pure function of (factory address, salt)).
        ///      Write-once in `_deployProxy`.
        mapping(bytes32 vaultId => address wallet) wallets;
        /// @dev Reverse of `wallets`. `bytes32(0)` means "not deployed by
        ///      this factory" — the `OnlyWallet` gate in `updateWalletOwner`.
        ///      Write-once in `_deployProxy`.
        mapping(address wallet => bytes32 vaultId) vaultIdOf;
        /// @dev Authoritative CURRENT classical owner of each wallet —
        ///      rotated only by the wallet's `updateWalletOwner` callback.
        mapping(address wallet => address owner) walletOwner;
        /// @dev Per-owner set of vaultIds. Tracks CURRENT classical owner —
        ///      the wallet's PQ ownership-transfer flow calls back into
        ///      `updateWalletOwner` to move the entry between owners.
        mapping(address owner => EnumerableSetLib.Bytes32Set) vaultIds;
        /// @dev Insertion-ordered set of vetted implementation codehashes.
        ///      Deprecated entries remain in the set to preserve index
        ///      stability.
        EnumerableSetLib.Bytes32Set vettedCode;
        /// @dev Implementation address for each vetted codehash. Re-bound on
        ///      `undeprecateImplementation` (same codehash ⇒ same behavior).
        mapping(bytes32 codehash => address walletImplementation) vettedWalletImpls;
        /// @dev Deprecation flags. Deprecated codehashes stay in `vettedCode`.
        mapping(bytes32 codehash => bool isDeprecated) deprecatedImpls;
        /// @dev Most recently vetted active implementation (backward-scan
        ///      recomputed on deprecate/undeprecate).
        address latestWalletImpl;
        // --- APPEND-ONLY below this line; never reorder above ---
        /// @dev Per-wallet CREATE3 salt (`keccak256(abi.encode(vaultId, commitment))`), the
        ///      unique registry key. Written in `_deployProxy`; read by `updateWalletOwner`
        ///      (to move the entry between owners' `vaultIds` sets) and `getWallets` (which
        ///      resolves each entry through `wallets[salt]`). `vaultIdOf` keeps the RAW vaultId
        ///      for the `WalletDeployed`/`WalletOwnerChanged` events.
        mapping(address wallet => bytes32 salt) saltOf;
    }

    /// @dev keccak256(abi.encode(uint256(keccak256("quip.storage.factory")) - 1))
    ///      & ~bytes32(uint256(0xff))
    bytes32 private constant _QUIP_FACTORY_STORAGE_SLOT =
        0x15a0b28fe60d62ff6b64e96a85fae11525a1125b5a8c3c139ce4790af3eb5500;

    /// @dev Returns the ERC-7201 namespaced storage layout.
    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := _QUIP_FACTORY_STORAGE_SLOT
        }
    }
}
