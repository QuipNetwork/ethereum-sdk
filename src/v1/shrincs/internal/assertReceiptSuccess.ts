// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { type TransactionReceipt } from "viem";

import { TransactionRevertedError } from "../errors.js";

export function assertReceiptSuccess(
  receipt: TransactionReceipt
): TransactionReceipt {
  if (receipt.status === "reverted") {
    throw new TransactionRevertedError(receipt.transactionHash);
  }
  return receipt;
}
