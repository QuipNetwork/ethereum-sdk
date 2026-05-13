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
export { entryPointV07Abi } from "./abi/EntryPointV07.js";

// Addresses, network helpers, codec, constants
export * from "./addresses.js";
export * as WotsCodec from "./wotsCodec.js";
export * from "./constants.js";

// Core SDK classes
export { QuipSigner } from "./signer.js";
export type { WinternitzKeyPair, WinternitzPublicKey } from "./signer.js";
export { QuipWalletClient, KeyType } from "./walletClient.js";
export { QuipClient } from "./factoryClient.js";
export { QuipPaymasterClient } from "./paymasterClient.js";

// Typed errors, simulation/gas helpers, and the staged userOp/paymaster/event
// surfaces (Phase 5+).
export * from "./errors.js";
export * from "./gas.js";
export * from "./userOp.js";
export * from "./paymasterClient.js";
export * from "./events.js";

// Re-export the aggregator types so callers can use them without reaching
// into the module subpaths.
export type {
  WalletState,
  WinternitzAddress,
  TransactionKeyOptions,
  BuildExecuteUserOpOptions,
  BuildExecuteUserOpResult,
  PreparedExecuteUserOp,
  SimulateUserOpResult,
} from "./walletClient.js";
export type { FactoryState } from "./factoryClient.js";
