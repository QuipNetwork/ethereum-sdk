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
  type PublicClient,
  type WalletClient,
  createPublicClient,
  createWalletClient,
  http,
} from "viem";
import { createAnvil } from "@viem/anvil";
import { foundry } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

import { quipFactoryAbi } from "../../../v1/abi/QuipFactory.js";
import { prepareTx, applyGasMultiplier, type ContractCallParams } from "../../../v1/gas.js";
import {
  GasEstimationError,
  BalanceTooLowError,
  FeeExceedsMaxError,
} from "../errors.js";
import { deployFactoryProxy } from "./utils/anvilFixture.js";

const ANVIL_PRIV_KEY =
  "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const account = privateKeyToAccount(ANVIL_PRIV_KEY);

// Distinct port from the other Anvil-based tests (8547, 8548).
const anvil = createAnvil({ port: 8549 });
let publicClient: PublicClient;
let walletClient: WalletClient;
let factoryAddress: Address;

const MAX_FEE = 10n ** 16n;

beforeAll(async () => {
  await anvil.start();
  const transport = http(`http://127.0.0.1:${anvil.port}`);
  publicClient = createPublicClient({ chain: foundry, transport });
  walletClient = createWalletClient({ chain: foundry, transport, account });

  ({ factoryAddress } = await deployFactoryProxy(
    walletClient,
    publicClient,
    account,
    MAX_FEE
  ));
}, 30_000);

afterAll(async () => {
  await anvil.stop().catch(() => {});
}, 10_000);

// Reusable contract-call params builder for QuipFactory.setExecuteFee — a
// state-mutating call we can drive from the deployer that may or may not
// revert depending on the fee value.
function setExecuteFeeCall(fee: bigint): ContractCallParams {
  return {
    address: factoryAddress,
    abi: quipFactoryAbi,
    functionName: "setExecuteFee",
    args: [fee],
    account: account.address,
  };
}

describe("prepareTx — happy path", () => {
  test("returns gas with default 20% buffer when no override", async () => {
    const prepared = await prepareTx({
      publicClient,
      contractParams: setExecuteFeeCall(MAX_FEE / 2n),
      totalValue: 0n,
    });
    expect(prepared.gas).toBeGreaterThan(0n);
    // 20% buffer means gas / 1.2 must be a sensible "raw estimate" range.
    // Hard to assert precisely without re-estimating, but at minimum we
    // can check the buffered value matches `applyGasMultiplier(estimate)`.
    const rawEstimate = await publicClient.estimateContractGas(
      setExecuteFeeCall(MAX_FEE / 2n) as Parameters<
        typeof publicClient.estimateContractGas
      >[0]
    );
    expect(prepared.gas).toBe(applyGasMultiplier(rawEstimate));
  });

  test("explicit opts.gas bypasses estimation entirely", async () => {
    const prepared = await prepareTx({
      publicClient,
      contractParams: setExecuteFeeCall(MAX_FEE / 2n),
      totalValue: 0n,
      opts: { gas: 999_999n },
    });
    expect(prepared.gas).toBe(999_999n);
  });

  test("custom gasMultiplier propagates", async () => {
    const prepared50 = await prepareTx({
      publicClient,
      contractParams: setExecuteFeeCall(MAX_FEE / 2n),
      totalValue: 0n,
      opts: { gasMultiplier: 1.5 },
    });
    const rawEstimate = await publicClient.estimateContractGas(
      setExecuteFeeCall(MAX_FEE / 2n) as Parameters<
        typeof publicClient.estimateContractGas
      >[0]
    );
    expect(prepared50.gas).toBe(applyGasMultiplier(rawEstimate, { gasMultiplier: 1.5 }));
  });

  test("forwards explicit fee + nonce overrides into PreparedTx", async () => {
    const prepared = await prepareTx({
      publicClient,
      contractParams: setExecuteFeeCall(MAX_FEE / 2n),
      totalValue: 0n,
      opts: {
        nonce: 42,
        maxFeePerGas: 30n * 10n ** 9n,
        maxPriorityFeePerGas: 1n * 10n ** 9n,
      },
    });
    expect(prepared.nonce).toBe(42);
    expect(prepared.fees.maxFeePerGas).toBe(30n * 10n ** 9n);
    expect(prepared.fees.maxPriorityFeePerGas).toBe(1n * 10n ** 9n);
    expect(prepared.fees.gasPrice).toBeUndefined();
  });
});

describe("prepareTx — contract-revert failure path", () => {
  test("contract revert surfaces as the decoded typed QuipError directly", async () => {
    let caught: unknown = null;
    try {
      await prepareTx({
        publicClient,
        contractParams: setExecuteFeeCall(MAX_FEE + 1n),
        totalValue: 0n,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(FeeExceedsMaxError);
    const decoded = caught as FeeExceedsMaxError;
    expect(decoded.fee).toBe(MAX_FEE + 1n);
    expect(decoded.maxFee).toBe(MAX_FEE);
  });

  test("opts.gas skips estimation — no contract reads happen", async () => {
    // With gas pinned, prepareTx never touches the contract for this
    // revert-prone call. No throw expected.
    const prepared = await prepareTx({
      publicClient,
      contractParams: setExecuteFeeCall(MAX_FEE + 1n),
      totalValue: 0n,
      opts: { gas: 200_000n, skipPreflightChecks: true },
    });
    expect(prepared.gas).toBe(200_000n);
  });
});

describe("prepareTx — preflight balance check", () => {
  test("BalanceTooLowError fires before gas estimation", async () => {
    // Use a fresh, unfunded account as the caller. Anvil EOA balance for
    // an untouched key is 0 wei.
    const broke = privateKeyToAccount(
      "0x0000000000000000000000000000000000000000000000000000000000000042"
    );
    let caught: unknown = null;
    try {
      await prepareTx({
        publicClient,
        contractParams: {
          address: factoryAddress,
          abi: quipFactoryAbi,
          functionName: "setExecuteFee",
          args: [MAX_FEE / 2n],
          account: broke.address,
        },
        totalValue: 10n ** 18n,
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(BalanceTooLowError);
    expect((caught as BalanceTooLowError).required).toBe(10n ** 18n);
    expect((caught as BalanceTooLowError).available).toBe(0n);
  });

  test("skipPreflightChecks lets the caller reach the gas estimation stage", async () => {
    // With the balance gate bypassed, prepareTx proceeds to estimation.
    // The broke account is NOT the factory owner, so estimateContractGas
    // reverts with OpenZeppelin's `OwnableUnauthorizedAccount`. We only
    // care that the failure originated past the balance gate — the exact
    // downstream class depends on whether viem can decode the Ownable
    // error against the factory ABI, which isn't this test's concern.
    const broke = privateKeyToAccount(
      "0x0000000000000000000000000000000000000000000000000000000000000043"
    );
    let caught: unknown = null;
    try {
      await prepareTx({
        publicClient,
        contractParams: {
          address: factoryAddress,
          abi: quipFactoryAbi,
          functionName: "setExecuteFee",
          args: [MAX_FEE / 2n],
          account: broke.address,
        },
        totalValue: 10n ** 18n,
        opts: { skipPreflightChecks: true },
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).not.toBeNull();
    expect(caught).not.toBeInstanceOf(BalanceTooLowError);
  });
});

describe("prepareTx — gas-estimation failure path", () => {
  test("non-contract estimation failures surface as GasEstimationError", async () => {
    // Point at an address with no code; viem's estimateContractGas can't
    // ABI-decode the empty return and throws.
    const noCodeAddr = "0xdeAdbEefdEAdbeefdEadbEEFdeadbeEFdEaDbeef" as Address;
    let caught: unknown = null;
    try {
      await prepareTx({
        publicClient,
        contractParams: {
          address: noCodeAddr,
          abi: quipFactoryAbi,
          functionName: "owner",
          account: account.address,
        },
        totalValue: 0n,
      });
    } catch (e) {
      caught = e;
    }
    // No-code call to `owner()` returns empty data — viem flags this as
    // an estimation failure, surfaced as GasEstimationError (no contract
    // selector to decode).
    expect(caught).toBeInstanceOf(GasEstimationError);
  });
});
