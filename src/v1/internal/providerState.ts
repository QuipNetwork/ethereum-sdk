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

import type { Address, Chain, PublicClient, WalletClient } from "viem";
import { AccountChangedError, ChainChangedError } from "../errors.js";

/// Every SDK client is bound to one `(chainId, account)` pair at
/// construction and never follows the provider when it switches. This
/// helper re-reads the provider's live state and throws a typed error on
/// divergence, failing closed instead of operating on stale assumptions.
///
/// PLACEMENT MATTERS: WOTS+ keys burn at `QuipSigner.sign(...)` time,
/// before broadcast. A stale provider caught at submit time (by viem's
/// chain check or the provider rejecting the `from`) has already cost the
/// caller a one-time key. Call this BEFORE any signing, not in the
/// transaction-submission path.
///
/// The account check asserts membership in `getAddresses()` rather than
/// equality with the active account: providers may expose several
/// permitted accounts and accept `eth_sendTransaction` from any of them.
export async function assertProviderState(params: {
  publicClient: PublicClient;
  expectedChainId: number;
  /// Pass both to also verify the bound account is still available.
  walletClient?: WalletClient;
  expectedAccount?: Address;
}): Promise<void> {
  const actualChainId = await params.publicClient.getChainId();
  if (actualChainId !== params.expectedChainId) {
    throw new ChainChangedError(params.expectedChainId, actualChainId);
  }
  if (params.walletClient && params.expectedAccount) {
    const accounts = await params.walletClient.getAddresses();
    const expected = params.expectedAccount.toLowerCase();
    if (!accounts.some((a) => a.toLowerCase() === expected)) {
      throw new AccountChangedError(params.expectedAccount, accounts);
    }
  }
}

/// Minimal viem `Chain` for the client's bound chainId. Passing this to
/// `writeContract` (instead of `chain: null`) re-enables viem's built-in
/// chain-consistency assertion at send time — a backstop behind
/// `assertProviderState`, and for local accounts it also pins the signed
/// transaction's `chainId` field to the bound chain. Only `id` is
/// meaningful; the other fields satisfy the `Chain` shape.
export function boundChain(chainId: number): Chain {
  return {
    id: chainId,
    name: `chain-${chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [] } },
  };
}
