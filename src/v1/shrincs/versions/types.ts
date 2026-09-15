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

import type { Abi, Address } from "viem";

/// Stable identifier for a ShrincsWallet implementation generation. `latest` is
/// the surface THIS SDK build was compiled against (the working-tree contract);
/// every other id names a FROZEN deployed generation the SDK must keep operating
/// and upgrading, whose specifics live under `versions/<id>/`.
export type WalletVersionId = "v1.0.1-beta.2" | "latest";

/// Per-generation quirks that change how the SDK must talk to a wallet. Kept as
/// an explicit capability record (not a version-number comparison) so each call
/// site reads a named trait rather than re-deriving it from an ordering.
export interface WalletVersionQuirks {
  /// The external view returning the ERC-1271 verifier commitment. Renamed
  /// `getErc1271Commitment` → `getErc1271PublicKeyCommitment` after beta.2.
  readonly erc1271CommitmentGetter:
    | "getErc1271Commitment"
    | "getErc1271PublicKeyCommitment";
  /// beta.2 stored the ERC-1271 verifier as a bare 32-byte commitment, so
  /// `setErc1271Key` took a `bytes32`; later generations take a full
  /// `PublicKey` bundle (tree-isolation audit fix). Gates whether the SDK may
  /// offer `setErc1271Key` against this wallet at all.
  readonly erc1271KeyArgument: "bytes32Commitment" | "publicKeyBundle";
  /// Whether the wallet exposes the per-word used-leaf bitmap view
  /// (`statefulLeafBitmapWord`), added after beta.2.
  readonly hasStatefulLeafBitmapWord: boolean;
  /// Whether a MIGRATING upgrade must present entirely fresh key bundles in the
  /// migrator payload (the spent-tree registry the isolation fix introduced).
  /// beta.2 predates lifetime spent-tree tracking, so a migrator that reuses a
  /// tree is rejected only on the NEW implementation being migrated TO.
  readonly enforcesSpentTreeFreshnessOnMigrate: boolean;
}

/// Everything the SDK needs to operate a wallet of a given generation: its
/// on-chain ABI (frozen per generation), the addresses it is known to be
/// deployed at, and its behavioral quirks.
export interface WalletVersionDescriptor {
  readonly id: WalletVersionId;
  /// Human-facing label for logs/errors (e.g. "V1.0.1-beta.2").
  readonly label: string;
  /// The wallet ABI for this generation. For `latest` this is the working-tree
  /// ABI; for a frozen generation it is the snapshot under `versions/<id>/`.
  readonly abi: Abi;
  /// Implementation addresses KNOWN to run this generation's bytecode. Empty for
  /// `latest` until it is deployed and pinned. Used to resolve a wallet's version
  /// from its installed ERC-1967 implementation pointer.
  readonly implementations: readonly Address[];
  readonly quirks: WalletVersionQuirks;
}
