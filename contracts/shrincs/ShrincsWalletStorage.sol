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

library ShrincsWalletStorage {
    /// @custom:storage-location erc7201:quip.storage.wallet.shrincs
    // ERC-7201 namespaced storage: field order is fixed for upgrade-safe layout;
    // repacking would collide storage on UUPS upgrade.
    // solhint-disable-next-line gas-struct-packing
    struct Layout {
        /// @dev Set once during `initialize`; effectively immutable after deployment.
        address payable walletFactory;
        /// @dev Commitment to the installed SHRINCS public-key bundle that authorizes every
        ///      normal operation (stateful path) and break-glass recovery (stateless path).
        ///      Only the 32-byte commitment is stored; callers always supply the full
        ///      `SHRINCS.PublicKey` bundle in calldata, which the SHRINCS library
        ///      re-validates against this commitment. Changes only via `rotateKey`
        ///      (stateful) or `recoverWallet` (stateless break-glass).
        bytes32 shrincsPublicKeyCommitment;
        /// @dev Full-bundle commitment (same shape as `shrincsPublicKeyCommitment`) of the
        ///      SEPARATE, dedicated SHRINCS bundle used solely for ERC-1271 contract-signature
        ///      verification — only its stateless half ever signs (view-safe). Isolated from the
        ///      main key so contract-signing never touches the recovery authority — enforced,
        ///      not assumed: every install path receives the full 1271 bundle and records both
        ///      of its trees in `spentStatefulTrees` / `spentStatelessTrees`, so it can never
        ///      share a tree with the main key (past or present) nor be reinstalled. Rotated
        ///      via `setErc1271Key` (a stateful action from the main key).
        bytes32 erc1271PublicKeyCommitment;
        /// @dev Installed-key epoch. Bound into every canonical action/rotation context and
        ///      incremented on every key rotation (`rotateKey` / `recoverWallet`) and on
        ///      migration, so signatures from a prior key epoch cannot be replayed.
        uint256 keyVersion;
        /// @dev Canonical SHRINCS action/rotation nonce — SEPARATE from the ERC-4337
        ///      EntryPoint nonce. Bound (live) into every `ActionContext`/`RotationContext`,
        ///      including ERC-1271 and upgrade contexts, and advanced once per consumed
        ///      signature (`transferOwnership` consumes two, netting +2). This is the wallet's
        ///      freshness/supersession mechanism: any landed action invalidates all outstanding
        ///      signed material — the passive invalidation the unordered leaf bitmap cannot
        ///      provide. Replaces the abandoned signed-`validUntil` deadline design.
        uint256 nonce;
        /// @dev Packed leaf-budget state for the main key (all fields rotate together):
        ///        - statefulLeavesUsed: count of consumed stateful leaves in the current epoch.
        ///          Backs `remainingStatefulSignatures()`; reset to 0 on every key rotation.
        ///          NOT the anti-replay mechanism — that is `usedStatefulLeafBitmap` below.
        ///        - maxSignatures: cached from the installed stateful bundle so the wallet can
        ///          reject signatures past the leaf budget and expose
        ///          `remainingStatefulSignatures()`.
        uint32 statefulLeavesUsed;
        uint32 maxSignatures;
        /// @dev Stateful-leaf anti-replay, namespaced by `keyVersion` so a rotation starts from a
        ///      fresh (all-unused) bitmap without clearing storage. A leaf is consumable once and
        ///      in ANY order (no sequential constraint), so out-of-order transaction landing never
        ///      reverts. `usedStatefulLeafBitmap[keyVersion][leafIndex >> 8]` bit
        ///      `leafIndex & 0xff`
        ///      is set when leaf `leafIndex` is consumed.
        mapping(uint256 keyVersion => mapping(uint256 wordIndex => uint256 usedBits))
            usedStatefulLeafBitmap;
        /// @dev Tree identities this wallet has ever installed, keyed by keccak256(pkSeed ‖ root).
        ///      A hash-based tree is one-time material for its lifetime, not per epoch: the
        ///      leaf bitmap resets on rotation, so re-installing a tree would resurrect its
        ///      consumed leaves. Every install path rejects a spent tree. Append-only.
        mapping(bytes32 statefulTreeId => bool) spentStatefulTrees;
        mapping(bytes32 statelessTreeId => bool) spentStatelessTrees;
    }

    /// @dev `keccak256(abi.encode(uint256(keccak256("quip.storage.wallet.shrincs")) - 1))
    ///      & ~bytes32(uint256(0xff))`.
    ///      Single source of truth for the ERC-7201 namespace base. The derived per-field
    ///      constant below is read by `ShrincsWallet`'s Yul from the same slot the library's
    ///      `layout()` writes to. Solidity's inline assembly only accepts direct numeric
    ///      constants, which is why the derived offset is its own hex literal rather than
    ///      `base + N`.
    bytes32 internal constant _SHRINCS_STORAGE_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc00;

    /// @dev Slot of `Layout.walletFactory` (field 0 of the namespace above). Read by
    ///      `initialize`/`migrate` Yul to re-establish the factory pin without an extra
    ///      keccak. `test/fixtures/ShrincsWallet.storageLayout.json` pins each field's slot
    ///      offset and fails the suite on any drift; a namespace rename above must
    ///      regenerate this literal with it.
    bytes32 internal constant _SHRINCS_FACTORY_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc00;

    /// @dev Returns the ERC-7201 namespaced storage layout.
    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := _SHRINCS_STORAGE_SLOT
        }
    }
}
