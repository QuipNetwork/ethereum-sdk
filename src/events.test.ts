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
import {
  type Hex,
  type Log,
  encodeAbiParameters,
  encodeEventTopics,
  keccak256,
  toFunctionSelector,
  zeroHash,
} from "viem";

import { quipWalletAbi } from "./abi/QuipWallet.js";
import {
  InvalidSignatureError,
  KeyInUseError,
  UnknownContractError,
} from "./errors.js";
import {
  parseExecutionReverted,
  parseExecutionSucceeded,
  parseKeyRotated,
  parseWalletReceipt,
} from "./events.js";

const WALLET = "0x1111111111111111111111111111111111111111" as const;
const TARGET = "0x2222222222222222222222222222222222222222" as const;

function makeKey(seed: bigint) {
  const toHex32 = (n: bigint) =>
    `0x${n.toString(16).padStart(64, "0")}` as Hex;
  return {
    publicSeed: toHex32(seed),
    publicKeyHash: toHex32(seed + 1n),
  };
}

/// Hand-craft a Log shape that matches what viem returns from
/// `getTransactionReceipt`. `topics` is the indexed-event encoding;
/// `data` is the abi-encoded non-indexed portion.
function makeLog(args: {
  topics: unknown;
  data: Hex;
  address?: `0x${string}`;
  blockNumber?: bigint;
  logIndex?: number;
}): Log {
  return {
    address: args.address ?? WALLET,
    topics: args.topics as [Hex, ...Hex[]],
    data: args.data,
    blockNumber: args.blockNumber ?? 1n,
    blockHash: zeroHash,
    transactionHash: zeroHash,
    transactionIndex: 0,
    logIndex: args.logIndex ?? 0,
    removed: false,
  } as Log;
}

describe("parseKeyRotated", () => {
  it("decodes oldKey + newKey", () => {
    const oldKey = makeKey(1n);
    const newKey = makeKey(2n);
    const topics = encodeEventTopics({
      abi: quipWalletAbi,
      eventName: "KeyRotated",
      args: {},
    });
    const data = encodeAbiParameters(
      [
        {
          type: "tuple",
          components: [
            { type: "bytes32", name: "publicSeed" },
            { type: "bytes32", name: "publicKeyHash" },
          ],
        },
        {
          type: "tuple",
          components: [
            { type: "bytes32", name: "publicSeed" },
            { type: "bytes32", name: "publicKeyHash" },
          ],
        },
      ],
      [oldKey, newKey]
    );
    const parsed = parseKeyRotated([makeLog({ topics, data })]);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].oldKey).toEqual(oldKey);
    expect(parsed[0].newKey).toEqual(newKey);
  });

  it("returns empty array when no matching log", () => {
    expect(parseKeyRotated([])).toEqual([]);
  });
});

describe("parseExecutionSucceeded", () => {
  it("decodes target/value/dataHash", () => {
    const topics = encodeEventTopics({
      abi: quipWalletAbi,
      eventName: "ExecutionSucceeded",
      args: { target: TARGET },
    });
    const dataHash = keccak256("0xdeadbeef");
    const data = encodeAbiParameters(
      [{ type: "uint256" }, { type: "bytes32" }],
      [123n, dataHash]
    );
    const parsed = parseExecutionSucceeded([makeLog({ topics, data })]);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].target.toLowerCase()).toBe(TARGET.toLowerCase());
    expect(parsed[0].value).toBe(123n);
    expect(parsed[0].dataHash).toBe(dataHash);
  });
});

describe("parseExecutionReverted", () => {
  /// Helper: produce an ExecutionReverted log carrying `result` as the
  /// inner revert bytes.
  function execRevertedLog(result: Hex): Log {
    const topics = encodeEventTopics({
      abi: quipWalletAbi,
      eventName: "ExecutionReverted",
      args: { target: TARGET },
    });
    const data = encodeAbiParameters(
      [{ type: "uint256" }, { type: "bytes32" }, { type: "bytes" }],
      [0n, keccak256("0x"), result]
    );
    return makeLog({ topics, data });
  }

  it("decodedReason resolves to InvalidSignatureError for that selector", () => {
    const sel = toFunctionSelector("InvalidSignature()") as Hex;
    const parsed = parseExecutionReverted([execRevertedLog(sel)]);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].result).toBe(sel);
    expect(parsed[0].decodedReason).toBeInstanceOf(InvalidSignatureError);
  });

  it("decodedReason resolves to KeyInUseError for that selector", () => {
    const sel = toFunctionSelector("KeyInUse()") as Hex;
    const parsed = parseExecutionReverted([execRevertedLog(sel)]);
    expect(parsed[0].decodedReason).toBeInstanceOf(KeyInUseError);
  });

  it("decodedReason is UnknownContractError for an out-of-surface selector", () => {
    // A made-up selector with valid abi-encoded args (single uint256 = 0).
    const revertBytes = ("0xdeadbeef" +
      "00".repeat(32)) as Hex;
    const parsed = parseExecutionReverted([execRevertedLog(revertBytes)]);
    // Unknown selectors decode with no errorName → UnknownContractError.
    expect(parsed[0].decodedReason).toBeInstanceOf(UnknownContractError);
  });

  it("decodedReason is null for empty revert (0x)", () => {
    const parsed = parseExecutionReverted([execRevertedLog("0x")]);
    expect(parsed[0].decodedReason).toBeNull();
  });
});

describe("parseWalletReceipt", () => {
  function rotatedLog() {
    const topics = encodeEventTopics({
      abi: quipWalletAbi,
      eventName: "KeyRotated",
      args: {},
    });
    const data = encodeAbiParameters(
      [
        {
          type: "tuple",
          components: [
            { type: "bytes32", name: "publicSeed" },
            { type: "bytes32", name: "publicKeyHash" },
          ],
        },
        {
          type: "tuple",
          components: [
            { type: "bytes32", name: "publicSeed" },
            { type: "bytes32", name: "publicKeyHash" },
          ],
        },
      ],
      [makeKey(1n), makeKey(2n)]
    );
    return makeLog({ topics, data });
  }

  function succeededLog() {
    const topics = encodeEventTopics({
      abi: quipWalletAbi,
      eventName: "ExecutionSucceeded",
      args: { target: TARGET },
    });
    const data = encodeAbiParameters(
      [{ type: "uint256" }, { type: "bytes32" }],
      [42n, keccak256("0x")]
    );
    return makeLog({ topics, data });
  }

  function rotationOnlyLog() {
    const topics = encodeEventTopics({
      abi: quipWalletAbi,
      eventName: "KeyRotationOnly",
      args: {},
    });
    const data = encodeAbiParameters(
      [
        {
          type: "tuple",
          components: [
            { type: "bytes32", name: "publicSeed" },
            { type: "bytes32", name: "publicKeyHash" },
          ],
        },
        {
          type: "tuple",
          components: [
            { type: "bytes32", name: "publicSeed" },
            { type: "bytes32", name: "publicKeyHash" },
          ],
        },
      ],
      [makeKey(10n), makeKey(20n)]
    );
    return makeLog({ topics, data });
  }

  it("returns 'executed' when ExecutionSucceeded + KeyRotated present", () => {
    const r = parseWalletReceipt([rotatedLog(), succeededLog()]);
    if (r === null) throw new Error("expected non-null result");
    if (r.kind !== "executed") throw new Error(`expected executed, got ${r.kind}`);
    expect(r.target.toLowerCase()).toBe(TARGET.toLowerCase());
    expect(r.value).toBe(42n);
    expect(r.rotation.oldKey).toEqual(makeKey(1n));
  });

  it("returns 'rotation-only' for KeyRotationOnly", () => {
    const r = parseWalletReceipt([rotationOnlyLog()]);
    if (r === null) throw new Error("expected non-null result");
    if (r.kind !== "rotation-only")
      throw new Error(`expected rotation-only, got ${r.kind}`);
    expect(r.currentKey).toEqual(makeKey(10n));
    expect(r.nextKey).toEqual(makeKey(20n));
  });

  it("returns null for an unrelated log set", () => {
    expect(parseWalletReceipt([])).toBeNull();
  });
});
