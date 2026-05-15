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
  applyGasMultiplier,
  resolveFeeOptions,
  resolveGasMultiplier,
  preflightBalanceCheck,
  DEFAULT_GAS_MULTIPLIER,
  MIN_GAS_MULTIPLIER,
  MAX_GAS_MULTIPLIER,
  type TxOptions,
} from "../gas.js";
import { BalanceTooLowError } from "../errors.js";

describe("applyGasMultiplier", () => {
  test("default 1.2 multiplier when no opts", () => {
    expect(applyGasMultiplier(100n)).toBe(120n);
    expect(DEFAULT_GAS_MULTIPLIER).toBe(1.2);
  });

  test("explicit gasMultiplier overrides default", () => {
    expect(applyGasMultiplier(100n, { gasMultiplier: 1.5 })).toBe(150n);
    expect(applyGasMultiplier(1000n, { gasMultiplier: 1.0 })).toBe(1000n);
    expect(applyGasMultiplier(100n, { gasMultiplier: 2.0 })).toBe(200n);
  });

  test("honors fractional multipliers to 3 decimal places", () => {
    // 1.137 × 1000 = 1137 → (1000 * 1137) / 1000 = 1137
    expect(applyGasMultiplier(1000n, { gasMultiplier: 1.137 })).toBe(1137n);
    // 1.05 (5% buffer) — useful granularity below 10%
    expect(applyGasMultiplier(1000n, { gasMultiplier: 1.05 })).toBe(1050n);
  });

  test("clamps above MAX_GAS_MULTIPLIER", () => {
    // 5.0 > 2.0 → cap at 2.0, so 100 × 2 = 200.
    expect(applyGasMultiplier(100n, { gasMultiplier: 5.0 })).toBe(200n);
    expect(MAX_GAS_MULTIPLIER).toBe(2.0);
  });

  test("clamps sub-1.0 + non-finite values to MIN (1.0)", () => {
    // Sub-1.0 values would under-budget gas; floor them up to 1.0 (no buffer)
    // rather than letting callers shoot themselves in the foot.
    expect(applyGasMultiplier(100n, { gasMultiplier: 0.5 })).toBe(100n);
    expect(applyGasMultiplier(100n, { gasMultiplier: -1 })).toBe(100n);
    // Non-finite values (NaN, Infinity) hit the `!Number.isFinite` branch
    // first and clamp to MIN, not MAX — safer default than auto-budgeting
    // 2× gas on a typo.
    expect(applyGasMultiplier(100n, { gasMultiplier: NaN })).toBe(100n);
    expect(applyGasMultiplier(100n, { gasMultiplier: Infinity })).toBe(100n);
    expect(MIN_GAS_MULTIPLIER).toBe(1.0);
  });

  test("preserves bigint precision on large estimates", () => {
    const big = 10n ** 18n;
    expect(applyGasMultiplier(big)).toBe((big * 1200n) / 1000n);
  });
});

describe("resolveGasMultiplier", () => {
  test("default when no opts set", () => {
    expect(resolveGasMultiplier()).toBe(1.2);
    expect(resolveGasMultiplier({})).toBe(1.2);
  });

  test("explicit gasMultiplier returned unchanged when in-range", () => {
    expect(resolveGasMultiplier({ gasMultiplier: 1.5 })).toBe(1.5);
  });

  test("clamp boundaries observable directly", () => {
    expect(resolveGasMultiplier({ gasMultiplier: 5.0 })).toBe(2.0);
    expect(resolveGasMultiplier({ gasMultiplier: 0.5 })).toBe(1.0);
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
      gasMultiplier: 1.5,
      maxFeePerGas: 5n * 10n ** 9n,
    };
    const fees = resolveFeeOptions(opts);
    expect(fees).toEqual({ maxFeePerGas: 5n * 10n ** 9n });
    expect("gas" in fees).toBe(false);
    expect("gasMultiplier" in fees).toBe(false);
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
