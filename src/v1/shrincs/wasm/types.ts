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

/// The subset of the `hashsigs-rs` WASM surface the SDK consumes.
export interface ShrincsWasmModule {
  supported_parameter_sets(): string[];
  shrincsKeygen(
    parameterSetId: string,
    seedHex: string,
    maxStatefulSignatures: number
  ): WasmShrincsKeypair;
  shrincsStatefulActionMessageHash(
    parameterSetId: string,
    expectedPublicKeyCommitmentHex: string,
    context: ActionContext
  ): string;
  shrincsStatelessActionMessageHash(
    parameterSetId: string,
    expectedPublicKeyCommitmentHex: string,
    context: ActionContext
  ): string;
  shrincsStatefulRotationMessageHash(
    parameterSetId: string,
    expectedPublicKeyCommitmentHex: string,
    currentPublicKey: ShrincsPublicKey,
    context: RotationContext,
    nextKey: StatefulRotationTarget
  ): string;
  shrincsFullRotationMessageHash(
    parameterSetId: string,
    expectedPublicKeyCommitmentHex: string,
    currentPublicKey: ShrincsPublicKey,
    context: RotationContext,
    nextKey: RotationTarget
  ): string;
  shrincs_verify_stateful_raw(
    parameterSetId: string,
    expectedPublicKeyCommitmentHex: string,
    publicKey: ShrincsPublicKey,
    messageHex: string,
    signature: StatefulSignature
  ): boolean;
  shrincs_verify_stateful_action(
    parameterSetId: string,
    expectedPublicKeyCommitmentHex: string,
    publicKey: ShrincsPublicKey,
    context: ActionContext,
    signature: StatefulSignature
  ): boolean;
  shrincs_verify_stateless_raw(
    parameterSetId: string,
    expectedPublicKeyCommitmentHex: string,
    publicKey: ShrincsPublicKey,
    messageHex: string,
    signature: StatelessSignature
  ): boolean;
  shrincs_verify_stateless_action(
    parameterSetId: string,
    expectedPublicKeyCommitmentHex: string,
    publicKey: ShrincsPublicKey,
    context: ActionContext,
    signature: StatelessSignature
  ): boolean;
}
