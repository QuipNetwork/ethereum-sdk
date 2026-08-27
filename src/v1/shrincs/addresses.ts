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
import {
  type Address,
  type Hex,
  encodeAbiParameters,
  keccak256,
  toHex,
} from "viem";

import {
  CANONICAL_ENTRYPOINT_V07,
  CHAIN_IDS,
  computeCreate3Address,
} from "../addresses.js";
import { UnsupportedNetworkError } from "../errors.js";

// Chain ids and the canonical EntryPoint are shared with the v1 SDK.
export { CANONICAL_ENTRYPOINT_V07, CHAIN_IDS } from "../addresses.js";

/// Per-chain Shrincs deployment handles. The EntryPoint is the canonical
/// ERC-4337 v0.7 singleton; the Shrincs handles are deterministic CREATE3
/// addresses (see below).
export interface ShrincsNetworkAddresses {
  EntryPoint: Address;
  /// ShrincsWallet implementation singleton — the vetted code the WalletFactory
  /// clones per user (parallel to `WOTSPlusImplementation`).
  ShrincsWalletImplementation: Address;
  /// Canonical ShrincsPaymaster (UUPS proxy) — the sponsorship address operators
  /// fund and the SDK's `ShrincsPaymasterClient` points at.
  ShrincsPaymaster: Address;
  /// ShrincsPaymaster implementation (UUPS upgrade target; rarely referenced
  /// directly by consumers).
  ShrincsPaymasterImpl: Address;
  /// The external `SHRINCS256sKeccak` ERC-7913 verifier both implementations
  /// pin as an immutable and delegate all signature crypto to. Deployed by
  /// hashsigs-solidity's own CreateX-based CREATE3 scripts (its
  /// `DEPLOYMENTS.md`), not this repo — same address on every chain.
  ShrincsVerifier: Address;
}

// Deterministic CREATE3 addresses produced by `script/PredictAddresses.s.sol`
// (run with `DEPLOY_OPERATOR` set). Shrincs contracts deploy straight through
// the CreateX singleton with SENDER-GUARDED salts, so each address is a
// function of (CreateX, DEPLOY_OPERATOR, salt preimage) — not the bytecode —
// and is identical on every chain reached by the same operator. The
// implementation salt preimages bind the verifier SCHEME tag on top of the
// version: `"QUIP:ShrincsWallet:V1.1:" ‖ PROFILE_ID` (and the paymaster-impl
// analog) where PROFILE_ID = keccak256("shrincs-256s-keccak") — the deployed
// verifier's constant `PROFILE_TAG()` — so implementations pinned to a
// different cryptographic scheme land at different addresses. The proxy
// preimage is the plain `QUIP:ShrincsPaymaster:Proxy:V1.1` (scheme-agnostic).
//
// The values below are derived for the canonical DEPLOY_OPERATOR
// `0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26` and deploy via
// `script/02_DeployShrincs.s.sol` (see DEPLOYMENTS.md).
const SHRINCS_WALLET_IMPLEMENTATION =
  "0xb84a596A6fB567FC4634b4f49212410D1193140e" as Address;
const SHRINCS_PAYMASTER_PROXY =
  "0xE38420930EBD214FE8FEb403dd66F4887AEF76E8" as Address;
const SHRINCS_PAYMASTER_IMPL =
  "0xfc5b4E75CA03c260255523DbbF56e93F9cbB5c59" as Address;
const SHRINCS_VERIFIER =
  "0x9154dA0BA19600C543a8c5ed1B1c44af415B5688" as Address;

/// Chains that share the CREATE3-deterministic (chain-independent) Shrincs
/// addresses captured under the `default` entry of `NETWORK_ADDRESSES`.
const SHRINCS_SUPPORTED_CHAIN_IDS: ReadonlySet<number> = new Set<number>([
  CHAIN_IDS.ETHEREUM_MAINNET,
  CHAIN_IDS.SEPOLIA,
  CHAIN_IDS.BASE,
  CHAIN_IDS.BASE_SEPOLIA,
  CHAIN_IDS.OPTIMISM,
  CHAIN_IDS.OPTIMISM_SEPOLIA,
  CHAIN_IDS.MIDL_TESTNET,
]);

/// Domain separator committed inside the full-width V1 identity hash.
/// MUST match Solidity `keccak256("QUIP_SHRINCS_IDENTITY_V1")` byte-for-byte.
export const V1_IDENTITY_DOMAIN = keccak256(toHex("QUIP_SHRINCS_IDENTITY_V1"));

/// Full-width identity commitment binding both key commitments and the intended owner.
/// MUST match on-chain `ShrincsWalletCodec.v1Commitment` byte-for-byte.
export function v1Commitment(
  statefulC: Hex,
  statelessC: Hex,
  owner: Address
): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "address" },
      ],
      [V1_IDENTITY_DOMAIN, statefulC, statelessC, owner]
    )
  );
}

/// Predict the counterfactual SHRINCS wallet address for
/// `(factory, statefulC, statelessC, owner)`. Use this before deploy to know
/// where to prefund. The CREATE3 salt is the V1 commitment, so the address is
/// a function of the two key commitments and the intended owner.
export function getShrincsWalletAddress(
  factoryAddress: Address,
  statefulC: Hex,
  statelessC: Hex,
  owner: Address
): Address {
  return computeCreate3Address(
    factoryAddress,
    v1Commitment(statefulC, statelessC, owner)
  );
}

/// Registry keyed by chain id, with a deterministic `default` entry shared by
/// every chain (CREATE3 addresses are chain-independent).
export const NETWORK_ADDRESSES: Record<number | "default", ShrincsNetworkAddresses> = {
  default: {
    EntryPoint: CANONICAL_ENTRYPOINT_V07,
    ShrincsWalletImplementation: SHRINCS_WALLET_IMPLEMENTATION,
    ShrincsPaymaster: SHRINCS_PAYMASTER_PROXY,
    ShrincsPaymasterImpl: SHRINCS_PAYMASTER_IMPL,
    ShrincsVerifier: SHRINCS_VERIFIER,
  },
};

/// Resolve the Shrincs addresses for `chainId`. Undefined → default;
/// registered entry → that entry; allowlisted shared-deployment chain →
/// default; otherwise throws `UnsupportedNetworkError`.
export function getShrincsAddresses(chainId?: number): ShrincsNetworkAddresses {
  if (chainId === undefined) return NETWORK_ADDRESSES.default;
  if (chainId in NETWORK_ADDRESSES) return NETWORK_ADDRESSES[chainId];
  if (SHRINCS_SUPPORTED_CHAIN_IDS.has(chainId))
    return NETWORK_ADDRESSES.default;
  throw new UnsupportedNetworkError(chainId);
}
