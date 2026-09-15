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
//
// WALLET VERSION RESOLVER. Existing wallets on chain run a FROZEN implementation
// generation; this SDK build is compiled against the `latest` (working-tree)
// surface. To keep operating and UPGRADING older wallets, the SDK resolves a
// wallet's generation from its installed ERC-1967 implementation pointer and
// then uses that generation's ABI + quirks. beta.2 specifics live under
// `versions/v1_0_1_beta2/`; the current surface stays the top-level default.

import type { Abi, Address, Hex, PublicClient } from "viem";
import { getAddress } from "viem";

import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import { UnknownWalletVersionError } from "../errors.js";
import type { WalletVersionDescriptor } from "./types.js";
import { v1_0_1_beta2 } from "./v1_0_1_beta2/index.js";

export type {
  WalletVersionDescriptor,
  WalletVersionId,
  WalletVersionQuirks,
} from "./types.js";
export { v1_0_1_beta2 } from "./v1_0_1_beta2/index.js";
export { shrincsWalletBeta2Abi } from "./v1_0_1_beta2/abi.js";

/// The ERC-1967 implementation slot
/// (`uint256(keccak256("eip1967.proxy.implementation")) - 1`).
export const ERC1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as const;

/// The generation THIS SDK build was compiled against — the working-tree
/// contract. Its `implementations` list is empty until the new implementation is
/// deployed and pinned; an on-chain wallet running unrecognized bytecode is
/// assumed to be this surface (the one the SDK's top-level ABI encodes).
export const LATEST_WALLET_VERSION: WalletVersionDescriptor = {
  id: "latest",
  label: "latest",
  abi: shrincsWalletAbi as unknown as Abi,
  implementations: [],
  quirks: {
    erc1271CommitmentGetter: "getErc1271PublicKeyCommitment",
    erc1271KeyArgument: "publicKeyBundle",
    hasStatefulLeafBitmapWord: true,
    enforcesSpentTreeFreshnessOnMigrate: true,
  },
};

/// Every generation the SDK can operate, newest surface last. The resolver scans
/// the FROZEN entries by their pinned implementation addresses; `LATEST` is the
/// fallback, never matched by address.
export const KNOWN_WALLET_VERSIONS: readonly WalletVersionDescriptor[] = [
  v1_0_1_beta2,
];

/// Resolve a generation from an installed implementation address. Lenient:
/// an address matching no frozen generation resolves to `LATEST_WALLET_VERSION`
/// (the surface this SDK build targets). Use `resolveWalletVersionStrict` when
/// an unrecognized implementation must fail loudly instead.
export function resolveWalletVersion(
  implementation: Address
): WalletVersionDescriptor {
  const normalized = getAddress(implementation);
  for (const version of KNOWN_WALLET_VERSIONS) {
    if (version.implementations.some((a) => getAddress(a) === normalized)) {
      return version;
    }
  }
  return LATEST_WALLET_VERSION;
}

/// Strict resolver: throws `UnknownWalletVersionError` for an implementation that
/// matches no frozen generation AND is not a pinned `latest` address. (Once the
/// new implementation is deployed and added to `LATEST_WALLET_VERSION`, it too
/// resolves here.)
export function resolveWalletVersionStrict(
  implementation: Address
): WalletVersionDescriptor {
  const normalized = getAddress(implementation);
  for (const version of [...KNOWN_WALLET_VERSIONS, LATEST_WALLET_VERSION]) {
    if (version.implementations.some((a) => getAddress(a) === normalized)) {
      return version;
    }
  }
  throw new UnknownWalletVersionError(normalized as Hex);
}

/// Read a wallet proxy's installed implementation from its ERC-1967 slot.
export async function readWalletImplementation(
  publicClient: PublicClient,
  walletAddress: Address
): Promise<Address> {
  const raw = await publicClient.getStorageAt({
    address: walletAddress,
    slot: ERC1967_IMPLEMENTATION_SLOT,
  });
  if (!raw) {
    throw new Error(
      `could not read ERC-1967 implementation slot of ${walletAddress}`
    );
  }
  // The address is the low 20 bytes of the 32-byte slot word.
  return getAddress(`0x${raw.slice(-40)}`);
}

/// Resolve a live wallet's generation by reading its installed implementation.
/// Lenient (unrecognized → `latest`); pass `{ strict: true }` to fail loudly.
export async function resolveWalletVersionFromChain(
  publicClient: PublicClient,
  walletAddress: Address,
  opts: { strict?: boolean } = {}
): Promise<WalletVersionDescriptor> {
  const implementation = await readWalletImplementation(
    publicClient,
    walletAddress
  );
  return opts.strict
    ? resolveWalletVersionStrict(implementation)
    : resolveWalletVersion(implementation);
}
