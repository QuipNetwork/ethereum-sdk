// Copyright (C) 2025 quip.network
//
// SPDX-License-Identifier: AGPL-3.0-or-later

import { encodeErrorResult, toFunctionSelector } from "viem";

import { shrincsWalletAbi } from "../abi/ShrincsWallet.js";
import {
  GuardedSlotTamperedError,
  MalformedCodecPayloadError,
  StaleStatefulLeafError,
  StatefulBudgetExhaustedError,
  InvalidSignatureError,
  UnknownContractError,
} from "../errors.js";
import { decodeRevertBytes } from "../internal/decodeError.js";

describe("shrincs error decoding", () => {
  it("decodes a zero-arg wallet error to its typed class", () => {
    const data = encodeErrorResult({ abi: shrincsWalletAbi, errorName: "StaleStatefulLeaf" });
    const decoded = decodeRevertBytes(data);
    expect(decoded).toBeInstanceOf(StaleStatefulLeafError);
    expect(decoded?.code).toBe("SHRINCS_STALE_STATEFUL_LEAF");
    expect(decoded?.selector).toBe(toFunctionSelector("StaleStatefulLeaf()"));
  });

  it("decodes StatefulBudgetExhausted and InvalidSignature", () => {
    expect(
      decodeRevertBytes(encodeErrorResult({ abi: shrincsWalletAbi, errorName: "StatefulBudgetExhausted" }))
    ).toBeInstanceOf(StatefulBudgetExhaustedError);
    expect(
      decodeRevertBytes(encodeErrorResult({ abi: shrincsWalletAbi, errorName: "InvalidSignature" }))
    ).toBeInstanceOf(InvalidSignatureError);
  });

  it("decodes MalformedPayload(uint256,uint256) preserving args", () => {
    const data = encodeErrorResult({
      abi: shrincsWalletAbi,
      errorName: "MalformedPayload",
      args: [64n, 12n],
    });
    const decoded = decodeRevertBytes(data) as MalformedCodecPayloadError;
    expect(decoded).toBeInstanceOf(MalformedCodecPayloadError);
    expect(decoded.expectedMin).toBe(64n);
    expect(decoded.actual).toBe(12n);
  });

  it("decodes GuardedSlotTampered(uint256) preserving the slot index", () => {
    const data = encodeErrorResult({
      abi: shrincsWalletAbi,
      errorName: "GuardedSlotTampered",
      args: [7n],
    });
    const decoded = decodeRevertBytes(data) as GuardedSlotTamperedError;
    expect(decoded).toBeInstanceOf(GuardedSlotTamperedError);
    expect(decoded.slotIndex).toBe(7);
  });

  it("maps an unknown 4-byte selector to UnknownContractError, and empty data to null", () => {
    expect(decodeRevertBytes("0xdeadbeef")).toBeInstanceOf(UnknownContractError);
    expect(decodeRevertBytes("0x")).toBeNull();
  });
});
