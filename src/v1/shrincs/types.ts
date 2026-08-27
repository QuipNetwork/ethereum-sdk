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

// The SDK's public data shapes, mirroring the on-chain SHRINCS structs
// (`SHRINCS.PublicKey`, `SHRINCS.Signature`, `SPHINCSPlusC.Signature`, and
// the canonical context structs) with Hex leaves.
//
// Through hashsigs-wasm 0.2.0-rc.2 these were derived from the wasm
// package's hex-string DTO types via a DeepHex mapped type. The current
// hashsigs-wasm (0.2.1) exchanges opaque `Uint8Array` ABI envelopes instead
// and ships no hex DTOs, so the SDK owns the canonical shapes and
// shrincsSigner.ts converts at the wasm boundary
// (`decodeStatefulEnvelope` / `decodeStatelessSignature`).
//
// SDK invariant note: for StatefulSignature, `authPath.length === leaf`
// (checked by the on-chain verifier for anti-replay).

export interface ShrincsPublicKey {
  /// 68 bytes: stateful `pkSeed ‖ root ‖ maxSignatures(u32 BE)`.
  statefulPublicKey: Hex;
  /// The 32-byte installed-key commitment (the on-chain bundle identity).
  publicKeyCommitment: Hex;
  /// Stateless (SPHINCS+C) public seed.
  pkSeed: Hex;
  /// Stateless hypertree root.
  hypertreeRoot: Hex;
}

export interface StatefulSignature {
  randomizer: Hex;
  counter: number;
  chains: Hex[];
  authPath: Hex[];
}

export interface WotsCSignature {
  randomizer: Hex;
  counter: number;
  chains: Hex[];
}

export interface ForsEntry {
  secretLeaf: Hex;
  authPath: Hex[];
}

export interface ForsSignature {
  randomizer: Hex;
  counter: number;
  entries: ForsEntry[];
}

export interface HypertreeLayerSignature {
  wotsCPkHash: Hex;
  wotsCSignature: WotsCSignature;
  authPath: Hex[];
}

export interface StatelessSignature {
  fors: ForsSignature;
  hypertree: HypertreeLayerSignature[];
}

export interface ActionContext {
  domainSeparator: Hex;
  nonce: Hex;
  keyVersion: Hex;
  actionType: Hex;
  payloadHash: Hex;
}

export interface RotationContext {
  domainSeparator: Hex;
  nonce: Hex;
  keyVersion: Hex;
}

/// Stateful-only rotation target (`rotateKey`): the incoming stateful
/// sub-key plus the commitment of the bundle it forms with the CURRENT
/// stateless half.
export interface StatefulRotationTarget {
  statefulPublicKey: Hex;
  publicKeyCommitment: Hex;
}

/// Full rotation target = the incoming bundle's public key (`recoverWallet` /
/// `transferOwnership`). Structurally a ShrincsPublicKey; kept as its own
/// name because the contracts type them separately.
export interface RotationTarget {
  statefulPublicKey: Hex;
  publicKeyCommitment: Hex;
  pkSeed: Hex;
  hypertreeRoot: Hex;
}

// The wasm module type, re-exported from upstream verbatim. This describes
// the RAW wasm surface (Uint8Array in/out); the Hex-typed DTOs above are
// what the rest of the SDK uses. Upstream signature changes surface as
// compile errors at the shrincsSigner.ts call sites.
export type { ShrincsWasmModule } from "@quip.network/hashsigs-wasm";
