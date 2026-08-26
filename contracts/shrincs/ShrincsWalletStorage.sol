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
        /// @dev Commitment to a SEPARATE, dedicated SHRINCS bundle used solely for ERC-1271
        ///      contract-signature verification (stateless, view-safe). Isolated from the
        ///      main key so contract-signing never touches the recovery authority. Rotated
        ///      via `setErc1271Key` (a stateful action from the main key).
        bytes32 erc1271StatelessCommitment;
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
        ///      reverts. `usedStatefulLeafBitmap[keyVersion][leafIndex >> 8]` bit `leafIndex & 0xff`
        ///      is set when leaf `leafIndex` is consumed.
        mapping(uint256 keyVersion => mapping(uint256 wordIndex => uint256 usedBits)) usedStatefulLeafBitmap;
    }

    /// @dev `keccak256(abi.encode(uint256(keccak256("quip.storage.wallet.shrincs")) - 1))
    ///      & ~bytes32(uint256(0xff))`.
    ///      Single source of truth for the ERC-7201 namespace base. The derived per-field
    ///      constants below are aliased into `ShrincsWallet`'s `storageStoreGuard` /
    ///      `delegateExecuteGuard` so the wallet's pre/post-snapshot Yul checks read from the
    ///      same slots the library's `layout()` writes to. Solidity's inline assembly only
    ///      accepts direct numeric constants, which is why each derived offset is its own hex
    ///      literal rather than `base + N`.
    bytes32 internal constant _SHRINCS_STORAGE_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc00;

    /// @dev Slots of the six guarded `Layout` scalar fields that `ShrincsWallet`'s guard
    ///      modifiers snapshot/check. Must be kept in lock-step with the field order of
    ///      `Layout` above; `test/fixtures/ShrincsWallet.storageLayout.json` pins each field's
    ///      slot offset and fails the suite on any drift. A namespace rename above must
    ///      regenerate every literal below together — they aren't independently meaningful.
    ///      The packed `{statefulLeavesUsed,maxSignatures}` scalars share
    ///      `_LEAF_STATE_SLOT`. The
    ///      `usedStatefulLeafBitmap` mapping occupies the next slot and is intentionally NOT
    ///      one of the guarded slots (see its field comment).
    bytes32 internal constant _SHRINCS_FACTORY_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc00;
    bytes32 internal constant _SHRINCS_COMMITMENT_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc01;
    bytes32 internal constant _ERC1271_COMMITMENT_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc02;
    bytes32 internal constant _KEY_VERSION_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc03;
    bytes32 internal constant _NONCE_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc04;
    bytes32 internal constant _LEAF_STATE_SLOT =
        0x156c3acdcccbf9925f3430f598565ae5b05788e8a68a7bf182e71c432eafdc05;

    /// @dev Returns the ERC-7201 namespaced storage layout.
    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := _SHRINCS_STORAGE_SLOT
        }
    }
}
