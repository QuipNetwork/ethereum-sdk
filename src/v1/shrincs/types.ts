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
import type {
  ActionContext as RawActionContext,
  ForsEntry as RawForsEntry,
  ForsSignature as RawForsSignature,
  HypertreeLayerSignature as RawHypertreeLayerSignature,
  RotationContext as RawRotationContext,
  RotationTarget as RawRotationTarget,
  ShrincsPublicKey as RawShrincsPublicKey,
  StatefulRotationTarget as RawStatefulRotationTarget,
  StatefulSignature as RawStatefulSignature,
  StatelessSignature as RawStatelessSignature,
  WotsCSignature as RawWotsCSignature,
} from "@quip.network/hashsigs-wasm";

/// Re-types every string leaf of a wasm DTO as viem `Hex`, preserving
/// structure; numbers/booleans pass through. Sound for the DTOs below:
/// every string leaf the wasm emits in them is 0x-prefixed lowercase hex
/// (audited upstream in hashsigs-ts internal/keys.ts; re-asserted at
/// runtime by tests/hashsigsBoundary.test.ts). Do NOT apply to the module
/// surface — e.g. `version()` returns a non-hex string.
export type DeepHex<T> = T extends string
  ? Hex
  : T extends readonly (infer U)[]
    ? DeepHex<U>[]
    : T extends object
      ? { [K in keyof T]: DeepHex<T[K]> }
      : T;

// The SDK's public data shapes — upstream's shapes, Hex-leaved. Upstream
// changes (new/renamed fields) flow through automatically on version bump.
// SDK invariant note: for StatefulSignature, `authPath.length === leaf`
// (checked by the on-chain verifier for anti-replay).
export type ShrincsPublicKey = DeepHex<RawShrincsPublicKey>;
export type StatefulSignature = DeepHex<RawStatefulSignature>;
export type StatelessSignature = DeepHex<RawStatelessSignature>;
export type ForsSignature = DeepHex<RawForsSignature>;
export type ForsEntry = DeepHex<RawForsEntry>;
export type WotsCSignature = DeepHex<RawWotsCSignature>;
export type HypertreeLayerSignature = DeepHex<RawHypertreeLayerSignature>;
export type ActionContext = DeepHex<RawActionContext>;
export type RotationContext = DeepHex<RawRotationContext>;
export type StatefulRotationTarget = DeepHex<RawStatefulRotationTarget>;
export type RotationTarget = DeepHex<RawRotationTarget>;
