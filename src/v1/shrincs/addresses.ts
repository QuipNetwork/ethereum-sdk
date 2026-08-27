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
import { type Address, type Hex, encodeAbiParameters, keccak256 } from "viem";

import {
  CANONICAL_ENTRYPOINT_V07,
  CHAIN_IDS,
  computeCreate3Address,
} from "../addresses.js";
import { MAX_DEPLOY_CHAINS } from "./constants.js";
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

// Deterministic CREATE3 addresses produced by `script/PredictAddresses.s.sol`.
// Shrincs contracts deploy straight through the CreateX singleton with
// SENDER-GUARDED salts, so each address is a function of (CreateX,
// CANONICAL_OPERATOR, salt preimage) — not the bytecode — and is identical on
// every chain reached by the same operator.
//
// Salt scheme: proxies are `V1.0.0` (permanent public identity), implementations
// are `V1.0.0-beta` (replaced as code changes). The implementation preimages
// additionally bind the verifier SCHEME tag —
// `"QUIP:ShrincsWallet:Impl:V1.0.0-beta:" ‖ PROFILE_ID` and the paymaster-impl
// analog, where PROFILE_ID = keccak256("shrincs-256s-keccak") is the deployed
// verifier's constant `PROFILE_TAG()` — so implementations pinned to a different
// cryptographic scheme land at different addresses. Proxy preimages carry no
// tag; an ERC-1967 proxy is scheme-agnostic.
//
// NOTE: THIS IS THE BASE MAINNET GENERATION. hashsigs moved its verifier deploys
// onto sender-guarded salts, relocating `SHRINCS256sKeccak` to the address
// below; the implementations bake it in as an immutable, so their salts moved
// with it. The PRIOR generation is still live on Base Sepolia and OP Sepolia
// against verifier `0x9154dA0BA19600C543a8c5ed1B1c44af415B5688`, at entirely
// different addresses (see DEPLOYMENTS.md). Those chains are legacy: this
// registry describes the current generation only, deliberately single-valued
// rather than per-chain, because CREATE3 ignores constructor args and a
// per-chain verifier would put DIFFERENT code at the SAME impl address.
//
// Derived for the canonical operator `0xc68B64770Da7914DEb0EF238b048a0Bf3B5f6A26`
// and deployed via `script/02_DeployShrincs.s.sol` (see DEPLOYMENTS.md).
const SHRINCS_WALLET_IMPLEMENTATION =
  "0x33d3949117c8Bba7A3637C96a564a817E00c5aE0" as Address;
const SHRINCS_PAYMASTER_PROXY =
  "0x077C06913777777DfABf951a5A0F8CA665764ac9" as Address;
const SHRINCS_PAYMASTER_IMPL =
  "0x995bDB6768F25822Faafb2c9b6Ad7Cf10CB6EEc3" as Address;
const SHRINCS_VERIFIER =
  "0xE6F2970bA30d59e8288b7007bA755828372457c3" as Address;

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

/// Committed, APPEND-ONLY deploy list (`e3r`). A chain's `quipDeployChainIndex`
/// is its 1-based position here (index 0 in the array → deploy leaf 1, never
/// leaf 0). The index binds each chain's deploy authorization to a distinct
/// reserved deploy leaf, so a deploy signature revealed on one chain never
/// enables a deploy on another.
///
/// PROCEDURE for a new chain: APPEND it to the END of this array (it takes the
/// next index), configure that chain's factory with the matching index at
/// setup, and release the new SDK version. NEVER reorder or remove an entry —
/// existing indices are permanent, so an append never reassigns an already
/// deployed wallet's deploy leaf. The list length must stay within
/// `MAX_DEPLOY_CHAINS` (the reserved deploy-leaf range).
export const DEPLOY_CHAIN_ORDER: readonly number[] = [
  CHAIN_IDS.ETHEREUM_MAINNET,
  CHAIN_IDS.SEPOLIA,
  CHAIN_IDS.BASE,
  CHAIN_IDS.BASE_SEPOLIA,
  CHAIN_IDS.OPTIMISM,
  CHAIN_IDS.OPTIMISM_SEPOLIA,
  CHAIN_IDS.MIDL_TESTNET,
];

/// Resolve the `quipDeployChainIndex` (1-based reserved deploy-leaf index) for
/// `chainId` from the committed deploy list. Throws `UnsupportedNetworkError`
/// for a chain not on the list.
export function quipDeployChainIndex(chainId: number): number {
  const pos = DEPLOY_CHAIN_ORDER.indexOf(chainId);
  if (pos === -1) throw new UnsupportedNetworkError(chainId);
  return pos + 1;
}

/// The CREATE3 deploy salt for a SHRINCS wallet (`e3r`). Binds the vault to the
/// main-key commitment, so the counterfactual address is a function of the key.
/// An attacker cannot land a different key at the same address, and the deploy
/// signature (verified in `initialize`) ensures only the key holder can deploy
/// there. MUST match the on-chain `keccak256(abi.encode(vaultId, commitment))`.
export function deployVaultSalt(vaultId: Hex, mainCommitment: Hex): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "bytes32" }],
      [vaultId, mainCommitment]
    )
  );
}

/// Predict the counterfactual SHRINCS wallet address for
/// `(factory, vaultId, mainCommitment)`. Use this before deploy to know where to
/// prefund. The address is bound to the key commitment (`e3r`).
export function getShrincsWalletAddress(
  factoryAddress: Address,
  vaultId: Hex,
  mainCommitment: Hex
): Address {
  return computeCreate3Address(
    factoryAddress,
    deployVaultSalt(vaultId, mainCommitment)
  );
}

// Load-time invariants on the committed deploy list: it must fit the reserved
// deploy-leaf range and hold no duplicate chain (a duplicate would map two
// chains to one deploy leaf).
if (DEPLOY_CHAIN_ORDER.length > MAX_DEPLOY_CHAINS) {
  throw new Error(
    `DEPLOY_CHAIN_ORDER (${DEPLOY_CHAIN_ORDER.length}) exceeds MAX_DEPLOY_CHAINS (${MAX_DEPLOY_CHAINS})`
  );
}
if (new Set(DEPLOY_CHAIN_ORDER).size !== DEPLOY_CHAIN_ORDER.length) {
  throw new Error("DEPLOY_CHAIN_ORDER contains a duplicate chain id");
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
///
/// The returned addresses are deterministic CREATE3 *predictions*. Membership
/// in the supported set means the address is derivable on that chain, not that
/// the contracts are live there. A caller that needs a live deployment must
/// confirm on-chain (`getCode`) before use.
export function getShrincsAddresses(chainId?: number): ShrincsNetworkAddresses {
  if (chainId === undefined) return NETWORK_ADDRESSES.default;
  if (chainId in NETWORK_ADDRESSES) return NETWORK_ADDRESSES[chainId];
  if (SHRINCS_SUPPORTED_CHAIN_IDS.has(chainId)) return NETWORK_ADDRESSES.default;
  throw new UnsupportedNetworkError(chainId);
}
