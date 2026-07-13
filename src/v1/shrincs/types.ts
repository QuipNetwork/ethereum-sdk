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

// SHRINCS data shapes. Field names + casing mirror the `hashsigs-rs` WASM JSON
// surface (camelCase) exactly, so objects returned by the signer flow straight
// into the WASM message-hash / verify entry points and into the codec's
// ABI-encoders with no renaming. The same shapes mirror the Solidity
// `ShrincsTypes` structs (`dependencies/@quip.network-hashsigs-solidity-0.1.0`).

/// SHRINCS long-lived public key bundle (stateful subkey + stateless root).
/// The hash suite (keccak-256) is fixed by the library and baked into every
/// canonical message hash, so the bundle carries no suite/parameter-set field.
export interface ShrincsPublicKey {
  /// 68 bytes: stateful pkSeed (32) ‖ stateful root (32) ‖ maxSignatures (4 BE).
  statefulPublicKey: Hex;
  /// keccak256 over the full bundle; the on-chain installed-key identity.
  publicKeyCommitment: Hex;
  /// Stateless SPHINCS+ public seed (32 bytes).
  pkSeed: Hex;
  /// Stateless SPHINCS+ public hypertree root (32 bytes).
  hypertreeRoot: Hex;
}

/// Stateful (fast-path) WOTS-C signature. `authPath.length === leaf index`, the
/// invariant the on-chain verifier checks for anti-replay.
export interface StatefulSignature {
  randomizer: Hex;
  counter: number;
  chains: Hex[];
  authPath: Hex[];
}

/// Few-time FORS signature at the bottom of the stateless hypertree.
export interface ForsSignature {
  randomizer: Hex;
  counter: number;
  entries: ForsEntry[];
}

export interface ForsEntry {
  secretLeaf: Hex;
  authPath: Hex[];
}

/// One hypertree layer authenticating a WOTS-C public key up to its parent root.
export interface HypertreeLayerSignature {
  treeIndex: bigint;
  leafIndex: number;
  wotsCPkHash: Hex;
  wotsCSignature: WotsCSignature;
  authPath: Hex[];
}

export interface WotsCSignature {
  randomizer: Hex;
  counter: number;
  chains: Hex[];
}

/// Stateless (recovery/rotation/ERC-1271) SPHINCS+-style signature.
export interface StatelessSignature {
  fors: ForsSignature;
  hypertree: HypertreeLayerSignature[];
}

/// Canonical signing context for a normal (stateful or stateless) wallet
/// action. All fields are 32-byte hex. `nonce` is the wallet's live
/// `actionNonce()` — bound into every context and advanced on every consumed
/// signature, so a landed action supersedes all outstanding signed material.
/// (Exception: the paymaster's sponsorship context binds nonce 0.)
export interface ActionContext {
  domainSeparator: Hex;
  nonce: Hex;
  keyVersion: Hex;
  actionType: Hex;
  payloadHash: Hex;
}

/// Context bound by stateless recovery/rotation messages.
export interface RotationContext {
  domainSeparator: Hex;
  nonce: Hex;
  keyVersion: Hex;
}

/// Incoming stateful-only subkey for `rotateKey` (reuses the current stateless
/// root, so it carries no pkSeed/hypertreeRoot).
export interface StatefulRotationTarget {
  statefulPublicKey: Hex;
  publicKeyCommitment: Hex;
}

/// Incoming full key bundle for `recoverWallet` / `transferOwnership`.
export interface RotationTarget {
  statefulPublicKey: Hex;
  publicKeyCommitment: Hex;
  pkSeed: Hex;
  hypertreeRoot: Hex;
}
