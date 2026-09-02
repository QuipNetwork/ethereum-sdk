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

/// On-chain hash-suite ids (uint32). The library hardcodes the suite into
/// every canonical message hash; the id is a client-agreement check carried
/// in install payloads, not a dispatch choice. The V4 verifier assigns
/// keccak = 1 and sha2 = 2, and keeps `SHRINCS.HASH_SUITE_UNSUPPORTED` as a
/// sentinel that never collides with a real suite id.
export const HASH_SUITE_KECCAK_256 = 1;
export const HASH_SUITE_SHA2_256 = 2;
export const HASH_SUITE_UNSUPPORTED = 0xffffffff;

/// WOTS-C chains revealed per stateful signature for the production profile.
/// (Structural cross-check for decoded signatures.)
export const STATEFUL_CHAINS = 64;

// Conservative ERC-4337 gas budgets. SHRINCS stateful verification (64 WOTS-C
// chains + an unbalanced Merkle auth path) is heavier than the WOTS+ wallet, so
// the verification ceilings sit above the v1 defaults. These are fallbacks only:
// `prepareTx` / userOp estimation override them with simulation results.
export const DEFAULT_VERIFICATION_GAS_LIMIT = 2_500_000n;
export const DEFAULT_CALL_GAS_LIMIT = 500_000n;
export const DEFAULT_PRE_VERIFICATION_GAS = 100_000n;
export const DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT = 2_500_000n;

/// Default sponsorship lifetime: `validUntil = now + this` when a caller does
/// not set `validUntil` explicitly. A sponsorship is a single-use leaf that
/// already binds sender, calldata and gas caps, so expiry is the ONLY control
/// that makes an issued-but-unsubmitted approval go stale by itself — and an
/// unbounded one (`validUntil: 0`) must be an explicit choice, never the
/// result of an omitted argument. Sized to cover an owner co-signature (a
/// hardware wallet included) plus bundler inclusion; every sponsorship that
/// expires unused strands its leaf until it is burned via `markLeavesUsed`.
export const DEFAULT_SPONSORSHIP_VALIDITY_SECONDS = 15 * 60;

/// Largest value the packed 6-byte `validUntil` / `validAfter` fields hold.
export const MAX_PAYMASTER_TIMESTAMP = 2 ** 48 - 1;
export const DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT = 100_000n;
