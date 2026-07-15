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
import { type Hex } from "viem";

import { KeyAlreadyBurnedError } from "./errors.js";

/// Atomic check-and-claim function for WOTS+ public seeds.
///
/// The SDK invokes this exactly once at the top of every `QuipSigner.sign(...)`
/// call and **awaits** it before the WOTS+ signature is produced. The contract:
///
/// - If the seed has already been claimed, throw `KeyAlreadyBurnedError`.
/// - Otherwise, mark the seed as claimed and return.
///
/// The function must be deterministic per `publicSeed`: once `consume(seed)`
/// returns (or resolves) successfully, every subsequent `consume(seed)` MUST
/// throw. Returns either `void` (sync default) or `Promise<void>` (async
/// implementations backed by Redis / Postgres / KMS / etc.). The signer
/// awaits the result either way, so the atomicity guarantee is preserved
/// for both shapes.
///
/// **Case-insensitive identity.** The `Hex` type is a hex-encoded byte string;
/// `0xABCD…` and `0xabcd…` represent the same seed. Custom `ConsumeKeyFn`
/// implementations MUST lowercase the seed before comparison (or otherwise
/// normalize), or a re-cased input will silently miss the burn record.
///
/// User-provided. The SDK ships `createInMemoryBurnSet()` as a process-local
/// default; production callers should back this with durable storage so a
/// process restart cannot resurrect a burned key. See `SDK_README.md` for the
/// operational contract.
export type ConsumeKeyFn = (publicSeed: Hex) => Promise<void> | void;

/// Concrete implementation returned by `createInMemoryBurnSet()`. Exposes
/// `consume` (the function the signer takes) and a `clear()` escape hatch
/// for tests. `clear()` is intentionally not part of `ConsumeKeyFn` — the
/// signer never calls it, and production callers should never need it.
export interface InMemoryBurnSet {
  consume: ConsumeKeyFn;
  /// Test-only. Drops every recorded burn. Never call from production code —
  /// once a key is broadcast, it is gone, and clearing the local record
  /// does not change that fact.
  clear(): void;
}

/// Process-local burn set. Backed by a `Set<Hex>` of lowercased public seeds.
/// Lives only for the lifetime of the JS object — a process restart loses
/// every recorded burn.
///
/// Inputs are normalized to lowercase before insertion / lookup so callers
/// passing `0xABCD…` and `0xabcd…` collide on the same record, matching the
/// case-insensitive identity of the underlying byte string.
///
/// Wire `consume` into `new QuipSigner(secret, burnSet.consume)`. For
/// production use, wrap the returned function (or write your own) to also
/// persist to durable storage before returning.
/** @deprecated WOTS+ family sunset — the burn-set mechanism is WOTS+-specific (SHRINCS uses stateful-leaf accounting instead). Fully functional for existing deployments. */
export function createInMemoryBurnSet(): InMemoryBurnSet {
  const burned = new Set<string>();
  return {
    consume(publicSeed: Hex): void {
      const normalized = publicSeed.toLowerCase();
      if (burned.has(normalized)) {
        throw new KeyAlreadyBurnedError(publicSeed);
      }
      burned.add(normalized);
    },
    clear(): void {
      burned.clear();
    },
  };
}
