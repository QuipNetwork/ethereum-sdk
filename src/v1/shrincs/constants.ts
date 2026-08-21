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

/// On-chain `ShrincsTypes` hash-suite ids (uint32). The library hardcodes
/// keccak-256 into every canonical message hash; the id is a client-agreement
/// check carried in install payloads, not a dispatch choice.
export const HASH_SUITE_KECCAK_256 = 1;
export const HASH_SUITE_UNSUPPORTED = 2;

/// WOTS-C chains revealed per stateful signature for the production profile.
/// (Structural cross-check for decoded signatures.)
export const STATEFUL_CHAINS = 64;

/// Size of the reserved deploy-leaf range at the low end of the main-key leaf
/// space (`e3r`). Leaves `[1 .. MAX_DEPLOY_CHAINS]` are reserved for deploy
/// authorizations, indexed by the factory's `quipDeployChainIndex`; the usable
/// signing budget is `[MAX_DEPLOY_CHAINS + 1 .. maxSignatures]`. This is the
/// ceiling on `quipDeployChainIndex` and MUST equal the on-chain constant.
/// DESIGN PARAMETER — confirm the value with the maintainer.
export const MAX_DEPLOY_CHAINS = 32;

// Conservative ERC-4337 gas budgets. SHRINCS stateful verification (64 WOTS-C
// chains + an unbalanced Merkle auth path) is heavier than the WOTS+ wallet, so
// the verification ceilings sit above the v1 defaults. These are fallbacks only:
// `prepareTx` / userOp estimation override them with simulation results.
export const DEFAULT_VERIFICATION_GAS_LIMIT = 2_500_000n;
export const DEFAULT_CALL_GAS_LIMIT = 500_000n;
export const DEFAULT_PRE_VERIFICATION_GAS = 100_000n;
export const DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT = 2_500_000n;
export const DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT = 100_000n;
