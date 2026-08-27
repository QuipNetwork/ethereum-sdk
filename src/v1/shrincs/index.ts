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

// ABIs
export { shrincsWalletAbi } from "./abi/ShrincsWallet.js";
export { shrincsPaymasterAbi } from "./abi/ShrincsPaymaster.js";

// Constants, addresses, codec
export * from "./constants.js";
export * from "./addresses.js";
export * as ShrincsCodec from "./shrincsCodec.js";

// Core SDK classes
export { ShrincsSigner, ShrincsKeyPair } from "./shrincsSigner.js";
export type {
  ShrincsKeygenOptions,
  DeriveKeyPairParams,
} from "./shrincsSigner.js";
export { ShrincsWalletClient, fetchShrincsWalletState } from "./shrincsWalletClient.js";
export type {
  ShrincsWalletState,
  ShrincsWalletClientParams,
  ShrincsTxKeyOptions,
  ExecuteParams,
  ExecuteCostEstimate,
  PreparedExecute,
  ShrincsCall,
  UserOpEnvelope,
} from "./shrincsWalletClient.js";
export type { CostEstimate } from "./estimateCost.js";
export { ShrincsPaymasterClient } from "./shrincsPaymasterClient.js";
export type {
  ShrincsVerifierState,
  ShrincsPaymasterClientParams,
} from "./shrincsPaymasterClient.js";
export { ShrincsFactoryClient } from "./shrincsFactoryClient.js";
export type {
  ShrincsFactoryClientParams,
  CreateShrincsWalletParams,
  GetShrincsWalletParams,
  EstimateCreationCostParams,
  CreationCostEstimate,
  Erc1271KeySpec,
} from "./shrincsFactoryClient.js";

// Typed errors, gas helpers, events, userOp staging surfaces
export * from "./errors.js";
export * from "./gas.js";
export * from "./events.js";
export * from "./userOp.js";

// Data shapes
export type {
  ShrincsPublicKey,
  StatefulSignature,
  StatelessSignature,
  ForsSignature,
  ForsEntry,
  HypertreeLayerSignature,
  WotsCSignature,
  ActionContext,
  RotationContext,
  StatefulRotationTarget,
  RotationTarget,
} from "./types.js";

// WASM loader (advanced; most callers go through `ShrincsSigner`).
export { loadShrincsWasm } from "@quip.network/hashsigs-wasm";
export type { ShrincsWasmModule, WasmShrincsKeypair } from "./types.js";
