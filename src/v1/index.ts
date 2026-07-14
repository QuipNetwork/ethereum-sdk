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

// Shared (wallet-family-agnostic) v1 surface. The SHRINCS client SDK lives at
// the `./v1/shrincs` subpath; the sunset WOTS+ family (QuipSigner,
// WOTSPlusImplementationClient, QuipClient, QuipPaymasterClient, WotsCodec,
// …) moved to `./deprecated/v1` and is no longer exported from this barrel.

// ABIs (generated). The WOTS-family ABIs still exist under the generated
// `./v1/abi` subpath — the live decode registry needs them — but are only
// re-exported from the `./deprecated/v1` barrel.
export { deployerAbi } from "./abi/Deployer.js";
export { quipFactoryAbi } from "./abi/QuipFactory.js";
export { entryPointV07Abi } from "./abi/EntryPointV07.js";

// Addresses & network helpers
export * from "./addresses.js";

// Typed errors and simulation/gas helpers
export * from "./errors.js";
export * from "./gas.js";

// Signature-scheme-agnostic ERC-4337 v0.7 codec (PackedUserOperation,
// userOpHash, gas-field packing) — shared by both wallet families.
export * from "./userOpCodec.js";
