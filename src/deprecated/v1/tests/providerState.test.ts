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
import type { Address, PublicClient, WalletClient } from "viem";
import {
  assertProviderState,
  boundChain,
} from "../../../v1/internal/providerState.js";
import { AccountChangedError, ChainChangedError } from "../errors.js";

const ACCOUNT = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" as Address;
const OTHER = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" as Address;

function fakePublicClient(chainId: number): PublicClient {
  return {
    getChainId: async () => chainId,
  } as unknown as PublicClient;
}

function fakeWalletClient(accounts: Address[]): WalletClient {
  return {
    getAddresses: async () => accounts,
  } as unknown as WalletClient;
}

describe("assertProviderState", () => {
  test("passes when chain matches and no account requested", async () => {
    await expect(
      assertProviderState({
        publicClient: fakePublicClient(1),
        expectedChainId: 1,
      })
    ).resolves.toBeUndefined();
  });

  test("passes when chain matches and bound account is available", async () => {
    await expect(
      assertProviderState({
        publicClient: fakePublicClient(1),
        expectedChainId: 1,
        walletClient: fakeWalletClient([OTHER, ACCOUNT]),
        expectedAccount: ACCOUNT,
      })
    ).resolves.toBeUndefined();
  });

  test("account comparison is case-insensitive", async () => {
    await expect(
      assertProviderState({
        publicClient: fakePublicClient(1),
        expectedChainId: 1,
        walletClient: fakeWalletClient([
          ACCOUNT.toLowerCase() as Address,
        ]),
        expectedAccount: ACCOUNT,
      })
    ).resolves.toBeUndefined();
  });

  test("throws ChainChangedError when provider chain diverges", async () => {
    const err = await assertProviderState({
      publicClient: fakePublicClient(8453),
      expectedChainId: 1,
    }).catch((e) => e);
    expect(err).toBeInstanceOf(ChainChangedError);
    expect(err.code).toBe("CHAIN_CHANGED");
    expect(err.expectedChainId).toBe(1);
    expect(err.actualChainId).toBe(8453);
  });

  test("chain check runs before account check", async () => {
    await expect(
      assertProviderState({
        publicClient: fakePublicClient(8453),
        expectedChainId: 1,
        walletClient: fakeWalletClient([]),
        expectedAccount: ACCOUNT,
      })
    ).rejects.toBeInstanceOf(ChainChangedError);
  });

  test("throws AccountChangedError when bound account is gone", async () => {
    const err = await assertProviderState({
      publicClient: fakePublicClient(1),
      expectedChainId: 1,
      walletClient: fakeWalletClient([OTHER]),
      expectedAccount: ACCOUNT,
    }).catch((e) => e);
    expect(err).toBeInstanceOf(AccountChangedError);
    expect(err.code).toBe("ACCOUNT_CHANGED");
    expect(err.expectedAccount).toBe(ACCOUNT);
    expect(err.availableAccounts).toEqual([OTHER]);
  });

  test("throws AccountChangedError when provider has no accounts", async () => {
    await expect(
      assertProviderState({
        publicClient: fakePublicClient(1),
        expectedChainId: 1,
        walletClient: fakeWalletClient([]),
        expectedAccount: ACCOUNT,
      })
    ).rejects.toBeInstanceOf(AccountChangedError);
  });

  test("skips account check when only walletClient is provided", async () => {
    await expect(
      assertProviderState({
        publicClient: fakePublicClient(1),
        expectedChainId: 1,
        walletClient: fakeWalletClient([]),
      })
    ).resolves.toBeUndefined();
  });
});

describe("boundChain", () => {
  test("carries the bound chain id", () => {
    expect(boundChain(8453).id).toBe(8453);
  });
});
