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
  applyGasBuffer,
  resolveFeeOptions,
  preflightBalanceCheck,
  DEFAULT_GAS_BUFFER_PERCENT,
  MAX_GAS_BUFFER_PERCENT,
  type TxOptions,
} from "./gas.js";
import { BalanceTooLowError } from "./errors.js";

describe("applyGasBuffer", () => {
  test("default 20% buffer when no opts", () => {
    expect(applyGasBuffer(100n)).toBe(120n);
    expect(DEFAULT_GAS_BUFFER_PERCENT).toBe(20);
  });

  test("explicit gasBufferPercent overrides default", () => {
    expect(applyGasBuffer(100n, { gasBufferPercent: 50 })).toBe(150n);
    expect(applyGasBuffer(1000n, { gasBufferPercent: 0 })).toBe(1000n);
    expect(applyGasBuffer(100n, { gasBufferPercent: 100 })).toBe(200n);
  });

  test("clamps above MAX_GAS_BUFFER_PERCENT", () => {
    // 200 > 100 → cap at 100, so 100 * 2 = 200.
    expect(applyGasBuffer(100n, { gasBufferPercent: 200 })).toBe(200n);
    expect(MAX_GAS_BUFFER_PERCENT).toBe(100);
  });

  test("clamps negative + non-finite values to 0", () => {
    expect(applyGasBuffer(100n, { gasBufferPercent: -50 })).toBe(100n);
    expect(applyGasBuffer(100n, { gasBufferPercent: NaN })).toBe(100n);
    expect(applyGasBuffer(100n, { gasBufferPercent: Infinity })).toBe(100n);
  });

  test("floors fractional percent", () => {
    // floor(33.7) = 33 → 100 * 1.33 = 133
    expect(applyGasBuffer(100n, { gasBufferPercent: 33.7 })).toBe(133n);
  });

  test("preserves bigint precision on large estimates", () => {
    const big = 10n ** 18n;
    expect(applyGasBuffer(big)).toBe((big * 120n) / 100n);
  });
});

describe("resolveFeeOptions", () => {
  test("empty opts → empty overrides", () => {
    expect(resolveFeeOptions()).toEqual({});
    expect(resolveFeeOptions({})).toEqual({});
  });

  test("only forwards explicitly-set fields", () => {
    const opts: TxOptions = {
      gas: 100_000n,
      gasBufferPercent: 50,
      maxFeePerGas: 5n * 10n ** 9n,
    };
    const fees = resolveFeeOptions(opts);
    expect(fees).toEqual({ maxFeePerGas: 5n * 10n ** 9n });
    expect("gas" in fees).toBe(false);
    expect("gasBufferPercent" in fees).toBe(false);
  });

  test("forwards full EIP-1559 pair", () => {
    const opts: TxOptions = {
      maxFeePerGas: 30n * 10n ** 9n,
      maxPriorityFeePerGas: 1n * 10n ** 9n,
    };
    expect(resolveFeeOptions(opts)).toEqual({
      maxFeePerGas: 30n * 10n ** 9n,
      maxPriorityFeePerGas: 1n * 10n ** 9n,
    });
  });

  test("forwards legacy gasPrice independently", () => {
    expect(resolveFeeOptions({ gasPrice: 5n * 10n ** 9n })).toEqual({
      gasPrice: 5n * 10n ** 9n,
    });
  });
});

describe("preflightBalanceCheck", () => {
  type Stub = { calls: bigint[]; balance: bigint };
  function stubClient(balance: bigint) {
    const stub: Stub = { calls: [], balance };
    const client = {
      getBalance: async ({ address: _ }: { address: string }) => {
        stub.calls.push(stub.balance);
        return stub.balance;
      },
    };
    return { stub, client: client as unknown as Parameters<typeof preflightBalanceCheck>[0] };
  }

  test("no-op when required is 0", async () => {
    const { stub, client } = stubClient(0n);
    await preflightBalanceCheck(client, "0x0000000000000000000000000000000000000001", 0n);
    expect(stub.calls.length).toBe(0);
  });

  test("no-op when required is negative", async () => {
    const { stub, client } = stubClient(0n);
    await preflightBalanceCheck(client, "0x0000000000000000000000000000000000000001", -1n);
    expect(stub.calls.length).toBe(0);
  });

  test("passes when balance exactly meets required", async () => {
    const { client } = stubClient(100n);
    await expect(
      preflightBalanceCheck(client, "0x0000000000000000000000000000000000000001", 100n)
    ).resolves.toBeUndefined();
  });

  test("throws BalanceTooLowError with required + available", async () => {
    const { client } = stubClient(50n);
    let caught: unknown = null;
    try {
      await preflightBalanceCheck(
        client,
        "0x0000000000000000000000000000000000000001",
        100n
      );
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(BalanceTooLowError);
    expect((caught as BalanceTooLowError).required).toBe(100n);
    expect((caught as BalanceTooLowError).available).toBe(50n);
  });
});
