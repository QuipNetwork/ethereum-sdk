// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
/// synchronous (the wasm module is already initialized).
export interface WasmShrincsKeypair {
  publicKey(): ShrincsPublicKey;
  /// Monotonic stateful signing — advances the keypair's internal leaf counter.
  signStatefulRaw(messageHex: string): StatefulSignature;
  /// Deterministic stateful signing at a caller-chosen leaf
  /// (`authPath.length === leaf`). Does not advance the internal counter.
  signStatefulRawAt(messageHex: string, leaf: number): StatefulSignature;
  signStatelessRaw(messageHex: string): StatelessSignature;
  exportSigningKey(): unknown;
}

/// The subset of the `hashsigs-rs` WASM surface the SDK consumes. The hash
/// suite (keccak-256) is baked into every canonical message hash by the
/// library, so no function takes a parameter-set/suite argument.
export interface ShrincsWasmModule {
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
