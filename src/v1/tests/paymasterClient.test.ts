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
import { describe, it, expect } from "@jest/globals";
import { type PublicClient, type WalletClient } from "viem";

import { CHAIN_IDS, NETWORK_ADDRESSES } from "../addresses.js";
import { QuipPaymasterClient } from "../paymasterClient.js";
import { UnsupportedNetworkError } from "../errors.js";

const account = "0x1111111111111111111111111111111111111111" as const;
const fakePublicClient = {} as unknown as PublicClient;
const fakeWalletClient = {} as unknown as WalletClient;

describe("QuipPaymasterClient.fromChain", () => {
  it("throws when the registered paymaster address is zero (chain has no deployment yet)", () => {
    // Default-shared chains (mainnet/sepolia/base/op…) now register the
    // canonical CREATE3 paymaster proxy address. MIDL_TESTNET still has
    // its placeholder zero address until that chain's paymaster lands.
    expect(NETWORK_ADDRESSES[CHAIN_IDS.MIDL_TESTNET].QuipPaymaster).toBe(
      "0x0000000000000000000000000000000000000000"
    );
    expect(() =>
      QuipPaymasterClient.fromChain({
        chainId: CHAIN_IDS.MIDL_TESTNET,
        publicClient: fakePublicClient,
        walletClient: fakeWalletClient,
        account,
      })
    ).toThrow(/no QuipPaymaster registered/i);
  });

  it("throws UnsupportedNetworkError for chains outside the supported set (delegates to getNetworkAddresses)", () => {
    expect(() =>
      QuipPaymasterClient.fromChain({
        chainId: 424242,
        publicClient: fakePublicClient,
        walletClient: fakeWalletClient,
        account,
      })
    ).toThrow(UnsupportedNetworkError);
  });

  it("succeeds when the registered paymaster address is non-zero (test override)", () => {
    // Temporarily inject a fake paymaster address for a registered chain
    // so we can exercise the happy-path construction without depending
    // on production deployment state.
    const FAKE_PAYMASTER =
      "0x9999999999999999999999999999999999999999" as const;
    const original = NETWORK_ADDRESSES.default.QuipPaymaster;
    NETWORK_ADDRESSES.default.QuipPaymaster = FAKE_PAYMASTER;
    try {
      const client = QuipPaymasterClient.fromChain({
        chainId: CHAIN_IDS.ETHEREUM_MAINNET,
        publicClient: fakePublicClient,
        walletClient: fakeWalletClient,
        account,
      });
      expect(client).toBeInstanceOf(QuipPaymasterClient);
      expect(client.getAddress()).toBe(FAKE_PAYMASTER);
    } finally {
      NETWORK_ADDRESSES.default.QuipPaymaster = original;
    }
  });
});
