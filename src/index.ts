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
export { deployerAbi } from "./abi/Deployer.js";
export { quipFactoryAbi } from "./abi/QuipFactory.js";
export { quipWalletAbi } from "./abi/QuipWallet.js";
export { quipPaymasterAbi } from "./abi/QuipPaymaster.js";

// Addresses, network helpers, codec, constants
export * from "./addresses.js";
export * as WotsCodec from "./wotsCodec.js";
export * from "./constants.js";

// Core SDK classes
export { QuipSigner } from "./signer.js";
export type { WinternitzKeyPair, WinternitzPublicKey } from "./signer.js";
export { QuipWalletClient, KeyType } from "./walletClient.js";
export { QuipClient } from "./factoryClient.js";

// Phase-staged module surfaces (currently empty placeholders)
export * from "./errors.js";
export * from "./gas.js";
export * from "./userOp.js";
export * from "./paymasterClient.js";
export * from "./events.js";

// TODO: SUPPORTED_NETWORKS and NetworkType may be unused — CHAIN_IDS in addresses.ts is canonical. Verify against frontend before removing.
export const SUPPORTED_NETWORKS = {
  SEPOLIA: "sepolia",
  SEPOLIA_OPTIMISM: "sepolia_optimism",
  SEPOLIA_BASE: "sepolia_base",
  MAINNET: "mainnet",
  BASE: "base",
  OPTIMISM: "optimism",
  MIDL_TESTNET: "midl",
} as const;

export type NetworkType =
  (typeof SUPPORTED_NETWORKS)[keyof typeof SUPPORTED_NETWORKS];
