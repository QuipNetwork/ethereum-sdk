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

// ── Stateless fixed layout (hashsigs-solidity 0.4.0 `StatelessLayout`, 256s) ──
// Mirrors of on-chain constants. `shrincsCodec.test.ts` pins every one of them
// against upstream's golden vector file, and the anvil smoke test proves the
// deployed wallet accepts what they produce.

/// `keccak256("shrincs-256s-keccak")` — `SHRINCSParams.PROFILE_ID`.
export const SHRINCS_PROFILE_ID =
  "0x32f573b453ffc4b3edb5db5c8c6f10d92aae60d6b7749116a86651f56e2a4878" as `0x${string}`;
/// `StatelessLayout.PK_LEN`: statefulPublicKey(68) ‖ commitment ‖ pkSeed ‖ root.
export const STATELESS_PK_BYTES = 164;
/// `StatelessLayout.PQ_LEN`: the FORS ‖ hypertree signature.
export const STATELESS_PQ_BYTES = 29_092;
/// `StatelessLayout.PAYLOAD_LEN`: what `verifyStateless` takes.
export const STATELESS_PAYLOAD_BYTES = STATELESS_PK_BYTES + STATELESS_PQ_BYTES;

/// ERC-1271 envelope magic, ASCII "QPCS" (`ShrincsWalletCodec.ERC1271_MAGIC`).
export const ERC1271_MAGIC = "0x51504353" as `0x${string}`;
/// Envelope version (`ShrincsWalletCodec.ERC1271_VERSION`); the wallet reports
/// the one it accepts through `erc1271Version()`.
export const ERC1271_VERSION = 1;
/// Owner ECDSA `r ‖ s ‖ v`.
export const ERC1271_ECDSA_BYTES = 65;
/// MAGIC(4) ‖ VERSION(1) ‖ PROFILE_ID(32) ‖ ECDSA(65) ‖ PK ‖ PQ.
export const ERC1271_SIGNATURE_BYTES =
  4 + 1 + 32 + ERC1271_ECDSA_BYTES + STATELESS_PAYLOAD_BYTES;

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
