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
import { type Address } from "viem";

import { CANONICAL_ENTRYPOINT_V07 } from "../addresses.js";
import { UnsupportedNetworkError } from "../errors.js";

// Chain ids and the canonical EntryPoint are shared with the v1 SDK.
export { CANONICAL_ENTRYPOINT_V07, CHAIN_IDS } from "../addresses.js";

/// Per-chain Shrincs deployment handles. The EntryPoint is the canonical
/// ERC-4337 v0.7 singleton; the Shrincs handles are deterministic CREATE3
/// addresses (see below).
export interface ShrincsNetworkAddresses {
  EntryPoint: Address;
  /// ShrincsWallet implementation singleton — the vetted code the QuipFactory
  /// clones per user (parallel to `WOTSPlusImplementation`).
  ShrincsWalletImplementation: Address;
  /// Canonical ShrincsPaymaster (UUPS proxy) — the sponsorship address operators
  /// fund and the SDK's `ShrincsPaymasterClient` points at.
  ShrincsPaymaster: Address;
  /// ShrincsPaymaster implementation (UUPS upgrade target; rarely referenced
  /// directly by consumers).
  ShrincsPaymasterImpl: Address;
}

// Deterministic CREATE3 addresses produced by `script/PredictAddresses.s.sol`
// (salts `QUIP:ShrincsWallet:V1.0`, `QUIP:ShrincsPaymaster:Impl:V1.0`,
// `QUIP:ShrincsPaymaster:Proxy:V1.0`). CREATE3 makes the address depend only on
// (Deployer, salt) — not the bytecode — so these are identical on every chain
// the canonical Deployer is bootstrapped on, and are stable once the
// DeployShrincs* scripts deploy with these salts.
const SHRINCS_WALLET_IMPLEMENTATION =
  "0xD1f3b80793D952551C26E31CC147e5df4149De76" as Address;
const SHRINCS_PAYMASTER_PROXY =
  "0x50a75bAF3a1eB13A266cA9a6b0ac916A62BC392F" as Address;
const SHRINCS_PAYMASTER_IMPL =
  "0x5F5210F324Ab9dce1080DB0fab0c3C55b51209b6" as Address;

/// Registry keyed by chain id, with a deterministic `default` entry shared by
/// every chain (CREATE3 addresses are chain-independent).
export const NETWORK_ADDRESSES: Record<number | "default", ShrincsNetworkAddresses> = {
  default: {
    EntryPoint: CANONICAL_ENTRYPOINT_V07,
    ShrincsWalletImplementation: SHRINCS_WALLET_IMPLEMENTATION,
    ShrincsPaymaster: SHRINCS_PAYMASTER_PROXY,
    ShrincsPaymasterImpl: SHRINCS_PAYMASTER_IMPL,
  },
};

/// Resolve the Shrincs addresses for `chainId`, falling back to the shared
/// `default` entry. Throws `UnsupportedNetworkError` only when an explicit,
/// unknown chain id is requested and no default applies.
export function getShrincsAddresses(chainId?: number): ShrincsNetworkAddresses {
  if (chainId !== undefined && chainId in NETWORK_ADDRESSES) {
    return NETWORK_ADDRESSES[chainId];
  }
  if (NETWORK_ADDRESSES.default) return NETWORK_ADDRESSES.default;
  throw new UnsupportedNetworkError(chainId ?? -1);
}
