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
  concat,
  hexToBytes,
  keccak256,
  pad,
  toHex,
} from "viem";

import {
  type WinternitzAddress,
  type WinternitzElements,
  PAYMASTER_AND_DATA_LEN,
  PAYMASTER_APPROVE_TAG,
  decodePaymasterAndData,
  packPaymasterAndData,
  paymasterOpCommitment,
  paymasterUserOpDigest,
} from "./wotsCodec.js";
import {
  DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
  DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
} from "./constants.js";

/// Local thin wrapper so the existing object-form test cases keep reading
/// cleanly. The codec function takes positional args (it mirrors the
/// Solidity-side concat); the wrapper exists only for test ergonomics.
function digest(params: {
  paymaster: `0x${string}`;
  chainId: bigint;
  currentVerifier: WinternitzAddress;
  nextVerifier: WinternitzAddress;
  sender: `0x${string}`;
  nonce: bigint;
  callData: `0x${string}`;
}) {
  return paymasterUserOpDigest(
    params.paymaster,
    params.chainId,
    params.currentVerifier.publicSeed,
    params.currentVerifier.publicKeyHash,
    params.nextVerifier.publicSeed,
    params.nextVerifier.publicKeyHash,
    params.sender,
    params.nonce,
    params.callData
  );
}

const PAYMASTER = "0x2222222222222222222222222222222222222222" as const;
const SENDER = "0x1111111111111111111111111111111111111111" as const;

function makeKey(seed: bigint): WinternitzAddress {
  const toHex32 = (n: bigint) =>
    `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;
  return {
    publicSeed: toHex32(seed),
    publicKeyHash: toHex32(seed + 1n),
  };
}

function makeSig(seed: bigint): WinternitzElements {
  const toHex32 = (n: bigint) =>
    `0x${n.toString(16).padStart(64, "0")}` as `0x${string}`;
  return {
    elements: Array.from({ length: 67 }, (_, i) => toHex32(seed + 100n + BigInt(i))),
  };
}

describe("PAYMASTER_APPROVE_TAG", () => {
  it("matches keccak256('quip.digest.paymasterApprove')", () => {
    const expected = keccak256(toHex("quip.digest.paymasterApprove"));
    expect(PAYMASTER_APPROVE_TAG).toBe(expected);
  });
});

describe("paymasterOpCommitment", () => {
  it("matches the contract formula keccak256(sender, nonce, keccak256(callData))", () => {
    const sender = SENDER;
    const nonce = 42n;
    const callData = "0xdeadbeef" as const;

    const expected = keccak256(
      concat([
        pad(sender as `0x${string}`, { size: 32, dir: "left" }),
        pad(toHex(nonce), { size: 32 }),
        keccak256(callData),
      ])
    );
    expect(paymasterOpCommitment(sender, nonce, callData)).toBe(expected);
  });

  it("differs when any field changes", () => {
    const base = paymasterOpCommitment(SENDER, 0n, "0x");
    expect(paymasterOpCommitment(SENDER, 1n, "0x")).not.toBe(base);
    expect(paymasterOpCommitment(SENDER, 0n, "0xff")).not.toBe(base);
    const otherSender = "0x9999999999999999999999999999999999999999" as const;
    expect(paymasterOpCommitment(otherSender, 0n, "0x")).not.toBe(base);
  });
});

describe("paymasterUserOpDigest", () => {
  it("matches the contract formula (PAYMASTER_APPROVE_TAG | chainId | paymaster | currentKey | nextKey | opCommitment)", () => {
    const chainId = 1n;
    const currentKey = makeKey(1n);
    const nextKey = makeKey(2n);
    const nonce = 42n;
    const callData = "0xabcd" as const;

    const opCommitment = paymasterOpCommitment(SENDER, nonce, callData);
    const expected = keccak256(
      concat([
        PAYMASTER_APPROVE_TAG,
        pad(toHex(chainId), { size: 32 }),
        pad(PAYMASTER as `0x${string}`, { size: 32, dir: "left" }),
        currentKey.publicSeed,
        currentKey.publicKeyHash,
        nextKey.publicSeed,
        nextKey.publicKeyHash,
        opCommitment,
      ])
    );

    const actual = digest({
      paymaster: PAYMASTER,
      chainId,
      currentVerifier: currentKey,
      nextVerifier: nextKey,
      sender: SENDER,
      nonce,
      callData,
    });
    expect(actual).toBe(expected);
  });

  it("differs when chainId / paymaster / verifiers / sender / nonce / callData change", () => {
    const ck = makeKey(1n);
    const nk = makeKey(2n);
    const base = digest({
      paymaster: PAYMASTER,
      chainId: 1n,
      currentVerifier: ck,
      nextVerifier: nk,
      sender: SENDER,
      nonce: 0n,
      callData: "0x",
    });

    const diff = (params: Parameters<typeof digest>[0]) => digest(params);

    expect(
      diff({
        paymaster: PAYMASTER,
        chainId: 8453n,
        currentVerifier: ck,
        nextVerifier: nk,
        sender: SENDER,
        nonce: 0n,
        callData: "0x",
      })
    ).not.toBe(base);
    expect(
      diff({
        paymaster: "0x0000000000000000000000000000000000000099",
        chainId: 1n,
        currentVerifier: ck,
        nextVerifier: nk,
        sender: SENDER,
        nonce: 0n,
        callData: "0x",
      })
    ).not.toBe(base);
    expect(
      diff({
        paymaster: PAYMASTER,
        chainId: 1n,
        currentVerifier: makeKey(99n),
        nextVerifier: nk,
        sender: SENDER,
        nonce: 0n,
        callData: "0x",
      })
    ).not.toBe(base);
    expect(
      diff({
        paymaster: PAYMASTER,
        chainId: 1n,
        currentVerifier: ck,
        nextVerifier: makeKey(99n),
        sender: SENDER,
        nonce: 0n,
        callData: "0x",
      })
    ).not.toBe(base);
    expect(
      diff({
        paymaster: PAYMASTER,
        chainId: 1n,
        currentVerifier: ck,
        nextVerifier: nk,
        sender: "0x0000000000000000000000000000000000000099",
        nonce: 0n,
        callData: "0x",
      })
    ).not.toBe(base);
    expect(
      diff({
        paymaster: PAYMASTER,
        chainId: 1n,
        currentVerifier: ck,
        nextVerifier: nk,
        sender: SENDER,
        nonce: 7n,
        callData: "0x",
      })
    ).not.toBe(base);
    expect(
      diff({
        paymaster: PAYMASTER,
        chainId: 1n,
        currentVerifier: ck,
        nextVerifier: nk,
        sender: SENDER,
        nonce: 0n,
        callData: "0xff",
      })
    ).not.toBe(base);
  });

  it("wrapper matches the codec function", () => {
    const ck = makeKey(0x11n);
    const nk = makeKey(0x22n);
    const viaWrapper = digest({
      paymaster: PAYMASTER,
      chainId: 31337n,
      currentVerifier: ck,
      nextVerifier: nk,
      sender: SENDER,
      nonce: 5n,
      callData: "0xc0ffee",
    });
    const viaCodec = paymasterUserOpDigest(
      PAYMASTER,
      31337n,
      ck.publicSeed,
      ck.publicKeyHash,
      nk.publicSeed,
      nk.publicKeyHash,
      SENDER,
      5n,
      "0xc0ffee"
    );
    expect(viaWrapper).toBe(viaCodec);
  });
});

describe("packPaymasterAndData", () => {
  it("produces 2272 bytes total", () => {
    const out = packPaymasterAndData({
      paymaster: PAYMASTER,
      validationGasLimit: DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
      postOpGasLimit: DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
      validUntil: 0,
      validAfter: 0,
      nextVerifier: makeKey(1n),
      sig: makeSig(2n),
    });
    expect(out.length).toBe(2 + PAYMASTER_AND_DATA_LEN * 2);
  });

  it("places paymaster, gas limits, time bounds, verifier, sig at correct offsets", () => {
    const validationGas = 1_000_000n;
    const postOpGas = 50_000n;
    const validUntil = 100;
    const validAfter = 50;
    const nv = makeKey(0x77n);
    const sig = makeSig(0x88n);
    const out = packPaymasterAndData({
      paymaster: PAYMASTER,
      validationGasLimit: validationGas,
      postOpGasLimit: postOpGas,
      validUntil,
      validAfter,
      nextVerifier: nv,
      sig,
    });
    const bytes = hexToBytes(out);

    // [0:20) paymaster
    expect(toHex(bytes.slice(0, 20)).toLowerCase()).toBe(
      PAYMASTER.toLowerCase()
    );
    // [20:36) validationGasLimit (uint128 big-endian)
    expect(BigInt(toHex(bytes.slice(20, 36)))).toBe(validationGas);
    // [36:52) postOpGasLimit
    expect(BigInt(toHex(bytes.slice(36, 52)))).toBe(postOpGas);
    // [52:58) validUntil
    expect(Number(BigInt(toHex(bytes.slice(52, 58))))).toBe(validUntil);
    // [58:64) validAfter
    expect(Number(BigInt(toHex(bytes.slice(58, 64))))).toBe(validAfter);
    // [64:96) nextVerifier.publicSeed
    expect(toHex(bytes.slice(64, 96))).toBe(nv.publicSeed);
    // [96:128) nextVerifier.publicKeyHash
    expect(toHex(bytes.slice(96, 128))).toBe(nv.publicKeyHash);
    // [128:2272) sig (67 × 32 bytes)
    expect(bytes.slice(128).length).toBe(67 * 32);
    for (let i = 0; i < 67; i++) {
      const start = 128 + i * 32;
      expect(toHex(bytes.slice(start, start + 32))).toBe(sig.elements[i]);
    }
  });

  it("defaults sig to zeros when omitted (for digest computation)", () => {
    const out = packPaymasterAndData({
      paymaster: PAYMASTER,
      validationGasLimit: 1n,
      postOpGasLimit: 1n,
      validUntil: 0,
      validAfter: 0,
      nextVerifier: makeKey(1n),
    });
    const bytes = hexToBytes(out);
    // All sig bytes (128..2272) should be zero.
    for (let i = 128; i < 2272; i++) {
      expect(bytes[i]).toBe(0);
    }
  });

  it("rejects out-of-range values", () => {
    const base = {
      paymaster: PAYMASTER,
      validationGasLimit: 1n,
      postOpGasLimit: 1n,
      validUntil: 0,
      validAfter: 0,
      nextVerifier: makeKey(1n),
    };
    expect(() =>
      packPaymasterAndData({ ...base, validationGasLimit: 1n << 128n })
    ).toThrow();
    expect(() =>
      packPaymasterAndData({ ...base, postOpGasLimit: 1n << 128n })
    ).toThrow();
    expect(() =>
      packPaymasterAndData({ ...base, validUntil: 2 ** 48 })
    ).toThrow();
    expect(() =>
      packPaymasterAndData({ ...base, validAfter: 2 ** 48 })
    ).toThrow();
  });
});

describe("decodePaymasterAndData", () => {
  it("round-trips through packPaymasterAndData", () => {
    const input = {
      paymaster: PAYMASTER,
      validationGasLimit: 1_234_567n,
      postOpGasLimit: 50_000n,
      validUntil: 9_999,
      validAfter: 42,
      nextVerifier: makeKey(0xabn),
      sig: makeSig(0xbeefn),
    };
    const packed = packPaymasterAndData(input);
    const out = decodePaymasterAndData(packed);
    expect(out.paymaster.toLowerCase()).toBe(PAYMASTER.toLowerCase());
    expect(out.validationGasLimit).toBe(input.validationGasLimit);
    expect(out.postOpGasLimit).toBe(input.postOpGasLimit);
    expect(out.validUntil).toBe(input.validUntil);
    expect(out.validAfter).toBe(input.validAfter);
    expect(out.nextVerifier.publicSeed).toBe(input.nextVerifier.publicSeed);
    expect(out.nextVerifier.publicKeyHash).toBe(
      input.nextVerifier.publicKeyHash
    );
    expect(out.sig.elements).toEqual(input.sig.elements);
  });

  it("throws on wrong length", () => {
    expect(() => decodePaymasterAndData("0xdead")).toThrow();
  });
});
