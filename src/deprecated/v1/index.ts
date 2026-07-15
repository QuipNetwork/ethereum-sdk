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

/**
 * @deprecated The WOTS+ wallet family is sunset — superseded by SHRINCS
 * (`@quip.network/ethereum-sdk/v1/shrincs`). This barrel preserves the full
 * historical `/v1` WOTS+ surface at `/deprecated/v1`; the code remains fully
 * functional for existing deployments but receives no new features.
 */

// ABIs
export { deployerAbi } from "../../v1/abi/Deployer.js";
export { walletFactoryAbi } from "../../v1/abi/WalletFactory.js";
export { wotsPlusImplementationAbi } from "../../v1/abi/WOTSPlusImplementation.js";
export { quipPaymasterAbi } from "../../v1/abi/QuipPaymaster.js";
export { entryPointV07Abi } from "../../v1/abi/EntryPointV07.js";

// Addresses, network helpers, codec, constants
export * from "../../v1/addresses.js";
export * as WotsCodec from "./wotsCodec.js";
export * from "./constants.js";

// Core SDK classes
export { QuipSigner } from "./signer.js";
export type { WinternitzKeyPair } from "./signer.js";
export { WOTSPlusImplementationClient } from "./walletClient.js";
export { QuipClient } from "./factoryClient.js";
export { QuipPaymasterClient } from "./paymasterClient.js";

// `KeyType` is canonically defined in `wotsCodec.ts` (it mirrors
// `WOTSPlusCodec.KeyType`). Re-exported here at the package barrel so
// callers don't have to reach into the codec subpath.
export { KeyType } from "./wotsCodec.js";

// Burn-set injection: every QuipSigner needs a `ConsumeKeyFn` to enforce
// WOTS+ one-time-use. `createInMemoryBurnSet()` is the process-local default;
// production callers should wrap or replace it with a durable backing store.
// (`KeyAlreadyBurnedError` is exported via the wildcard re-export of
// `./errors.js` above — callers writing their own `consume` import it from
// the package barrel and throw it on a reused seed.)
export { createInMemoryBurnSet } from "./burnSet.js";
export type { ConsumeKeyFn, InMemoryBurnSet } from "./burnSet.js";

// Typed errors, simulation/gas helpers, and the staged userOp/paymaster/event
// surfaces (Phase 5+).
export * from "./errors.js";
export * from "../../v1/gas.js";
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
export type { PackedUserOperation } from "./wotsCodec.js";
