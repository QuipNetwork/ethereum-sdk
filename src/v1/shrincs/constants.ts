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

/// The only SHRINCS profile shipped today. This is the WASM string id consumed
/// by `shrincsKeygen` / the message-hash / verify entry points.
export const PARAMETER_SET_ID = "sphincs-256s-keccak-q20" as const;

/// On-chain `ShrincsTypes.ParameterSetId` enum (uint8). Mirror of the Solidity
/// enum; used when ABI-encoding the `PublicKey`/rotation-target structs.
export enum ParameterSetId {
  Sphincs256sKeccakQ20 = 0,
  Unsupported = 1,
}

const ID_BY_ENUM: Record<number, string> = {
  [ParameterSetId.Sphincs256sKeccakQ20]: PARAMETER_SET_ID,
};

const ENUM_BY_ID: Record<string, ParameterSetId> = {
  [PARAMETER_SET_ID]: ParameterSetId.Sphincs256sKeccakQ20,
};

/// Map the WASM string parameter-set id to the on-chain enum value.
export function parameterSetIdToEnum(parameterSetId: string): ParameterSetId {
  const e = ENUM_BY_ID[parameterSetId];
  if (e === undefined) {
    throw new Error(`Unsupported SHRINCS parameter set: ${parameterSetId}`);
  }
  return e;
}

/// Map the on-chain enum value back to the WASM string id.
export function parameterSetEnumToId(parameterSetId: number): string {
  const id = ID_BY_ENUM[parameterSetId];
  if (id === undefined) {
    throw new Error(`Unsupported SHRINCS parameter-set enum: ${parameterSetId}`);
  }
  return id;
}

/// WOTS-C chains revealed per stateful signature for the production profile.
/// (Structural cross-check for decoded signatures.)
export const STATEFUL_CHAINS = 64;

/// Number of confirmations awaited after a write, unless overridden.
export const DEFAULT_CONFIRMATIONS = 1;

// Conservative ERC-4337 gas budgets. SHRINCS stateful verification (64 WOTS-C
// chains + an unbalanced Merkle auth path) is heavier than the WOTS+ wallet, so
// the verification ceilings sit above the v1 defaults. These are fallbacks only:
// `prepareTx` / userOp estimation override them with simulation results.
export const DEFAULT_VERIFICATION_GAS_LIMIT = 2_500_000n;
export const DEFAULT_CALL_GAS_LIMIT = 500_000n;
export const DEFAULT_PRE_VERIFICATION_GAS = 100_000n;
export const DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT = 2_500_000n;
export const DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT = 100_000n;
