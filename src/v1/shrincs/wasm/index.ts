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

// The hashsigs boundary. The SHRINCS wasm comes from the published
// `@quip.network/hashsigs-wasm` package (the same build our sibling
// `@quip.network/hashsigs` wraps) instead of a vendored wasm-bindgen build.
// Its own exports map carries the `browser` condition (Node: lazy
// createRequire of the CJS target; browser: base64-inlined web target), so
// this SDK no longer needs a `"browser"` field, wasm copy steps, or loaders.
//
// The interfaces below are the Hex-typed view of the exact subset the SDK
// consumes. Upstream types every hex leaf as plain `string`; at runtime the
// wasm emits 0x-prefixed lowercase hex on every output leaf and accepts both
// prefixed and bare hex on input (audited upstream in hashsigs-ts
// `internal/keys.ts`; re-asserted at runtime by tests/hashsigsBoundary
// .test.ts). That invariant justifies the single narrowing cast in
// `loadShrincsWasm` — the only cast in the codebase. Inputs need nothing:
// `Hex` is assignable to `string`.
//
// RULE: hashsigs-wasm types appear in THIS file (and type-only in
// ../types.ts) and nowhere else in the SDK.

import {
  loadShrincsWasm as loadRawShrincsWasm,
  type ShrincsWasmModule as RawShrincsWasmModule,
} from "@quip.network/hashsigs-wasm";

import {
  type ActionContext,
  type RotationContext,
  type RotationTarget,
  type ShrincsPublicKey,
  type StatefulRotationTarget,
  type StatefulSignature,
  type StatelessSignature,
} from "../types.js";

/// A live SHRINCS keypair handle backed by the WASM signing key. Methods are
/// synchronous (the wasm module is already initialized). This is the subset
/// the SDK consumes — the auto-advancing `signStatefulRaw` (whose raw return
/// type changed to `StatefulSignResult` in 0.2.0-rc1) and the signing-key
/// export/import surface exist upstream but are unused here: the on-chain
/// used-leaf bitmap is authoritative, so the SDK only ever signs at an
/// explicit caller-chosen leaf.
export interface WasmShrincsKeypair {
  publicKey(): ShrincsPublicKey;
  /// Deterministic stateful signing at a caller-chosen leaf
  /// (`authPath.length === leaf`). Does not advance the internal counter.
  signStatefulRawAt(messageHex: string, leaf: number): StatefulSignature;
  signStatelessRaw(messageHex: string): StatelessSignature;
}

/// The subset of the `hashsigs-rs` WASM surface the SDK consumes. The hash
/// suite (keccak-256) is baked into every canonical message hash by the
/// library, so no function takes a parameter-set/suite argument.
export interface ShrincsWasmModule {
  version(): string;
  shrincsKeygen(
    seedHex: string,
    maxStatefulSignatures: number
  ): WasmShrincsKeypair;
  shrincsStatefulActionMessageHash(
    expectedPublicKeyCommitmentHex: string,
    context: ActionContext
  ): string;
  shrincsStatelessActionMessageHash(
    expectedPublicKeyCommitmentHex: string,
    context: ActionContext
  ): string;
  shrincsStatefulRotationMessageHash(
    expectedPublicKeyCommitmentHex: string,
    currentPublicKey: ShrincsPublicKey,
    context: RotationContext,
    nextKey: StatefulRotationTarget
  ): string;
  shrincsFullRotationMessageHash(
    expectedPublicKeyCommitmentHex: string,
    currentPublicKey: ShrincsPublicKey,
    context: RotationContext,
    nextKey: RotationTarget
  ): string;
  shrincsVerifyStatefulRaw(
    expectedPublicKeyCommitmentHex: string,
    publicKey: ShrincsPublicKey,
    messageHex: string,
    signature: StatefulSignature
  ): boolean;
  shrincsVerifyStatefulAction(
    expectedPublicKeyCommitmentHex: string,
    publicKey: ShrincsPublicKey,
    context: ActionContext,
    signature: StatefulSignature
  ): boolean;
  shrincsVerifyStatelessRaw(
    expectedPublicKeyCommitmentHex: string,
    publicKey: ShrincsPublicKey,
    messageHex: string,
    signature: StatelessSignature
  ): boolean;
  shrincsVerifyStatelessAction(
    expectedPublicKeyCommitmentHex: string,
    publicKey: ShrincsPublicKey,
    context: ActionContext,
    signature: StatelessSignature
  ): boolean;
}

// ── compile-time drift guard ──────────────────────────────────────────────
// If upstream renames or removes anything this SDK consumes, fail the build
// here — loudly — instead of letting the cast below hide it.
type RawKeypair = ReturnType<RawShrincsWasmModule["shrincsKeygen"]>;
type _AssertModuleSubset = Exclude<
  keyof ShrincsWasmModule,
  keyof RawShrincsWasmModule
> extends never
  ? true
  : never;
type _AssertKeypairSubset = Exclude<
  keyof WasmShrincsKeypair,
  keyof RawKeypair
> extends never
  ? true
  : never;
const _moduleSubsetOk: _AssertModuleSubset = true;
const _keypairSubsetOk: _AssertKeypairSubset = true;
void _moduleSubsetOk;
void _keypairSubsetOk;

/// Load the SHRINCS WASM bindings. Lazy and cached by the upstream loader
/// (one wasm instance process-wide, shared with any other consumer of
/// `@quip.network/hashsigs-wasm` in the same app — including
/// `@quip.network/hashsigs` itself).
export async function loadShrincsWasm(): Promise<ShrincsWasmModule> {
  return (await loadRawShrincsWasm()) as unknown as ShrincsWasmModule;
}
