// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type TransactionReceipt } from "viem";

import { TransactionRevertedError } from "../errors.js";
import { assertReceiptSuccess } from "../internal/assertReceiptSuccess.js";

const HASH =
  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const;

function receipt(status: TransactionReceipt["status"]): TransactionReceipt {
  return { status, transactionHash: HASH } as unknown as TransactionReceipt;
}

describe("assertReceiptSuccess", () => {
  it("throws TransactionRevertedError when the receipt status is reverted", () => {
    expect(() => assertReceiptSuccess(receipt("reverted"))).toThrow(
      TransactionRevertedError
    );
  });

  it("returns the same receipt object when the receipt status is success", () => {
    const r = receipt("success");
    expect(assertReceiptSuccess(r)).toBe(r);
  });
});
