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
/// call. The contract:
///
/// - If the seed has already been claimed, throw `KeyAlreadyBurnedError`.
/// - Otherwise, mark the seed as claimed and return.
///
/// The function must be deterministic per `publicSeed`: once `consume(seed)`
/// returns successfully, every subsequent `consume(seed)` MUST throw.
///
/// User-provided. The SDK ships `createInMemoryBurnSet()` as a process-local
/// default; production callers should back this with durable storage so a
/// process restart cannot resurrect a burned key. See `SDK_README.md` for the
/// operational contract.
export type ConsumeKeyFn = (publicSeed: Hex) => void;

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

/// Process-local burn set. Backed by a `Set<Hex>` over public seeds. Lives
/// only for the lifetime of the JS object — a process restart loses every
/// recorded burn.
///
/// Wire `consume` into `new QuipSigner(secret, burnSet.consume)`. For
/// production use, wrap the returned function (or write your own) to also
/// persist to durable storage before returning.
export function createInMemoryBurnSet(): InMemoryBurnSet {
  const burned = new Set<Hex>();
  return {
    consume(publicSeed: Hex): void {
      if (burned.has(publicSeed)) {
        throw new KeyAlreadyBurnedError(publicSeed);
      }
      burned.add(publicSeed);
    },
    clear(): void {
      burned.clear();
    },
  };
}
