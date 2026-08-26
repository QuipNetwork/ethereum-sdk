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
  concat,
  hexToBytes,
  keccak256,
  pad,
  slice,
  toHex,
} from "viem";

import {
  type PackedUserOperation,
  type WinternitzAddress,
  type WinternitzElements,
  PAYMASTER_AND_DATA_LEN,
  PAYMASTER_APPROVE_TAG,
  PAYMASTER_SIG_OFFSET,
  decodePaymasterAndData,
  packPaymasterAndData,
  paymasterUserOpDigest,
  userOpBindingHash,
} from "../wotsCodec.js";
import {
  DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
  DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
} from "../constants.js";

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

/// Construct a baseline `PackedUserOperation` with a fully staged
/// paymasterAndData prefix (zero-byte sig placeholder). Each test starts
/// from this and mutates one field to assert the binding/digest reacts.
function baselineUserOp(): PackedUserOperation {
  return {
    sender: SENDER,
    nonce: 7n,
    initCode: "0xaabbcc",
    callData: "0xddeeff00",
    accountGasLimits: pad(toHex(0x1234n), { size: 32 }),
    preVerificationGas: 21_000n,
    gasFees: pad(toHex(0x5678n), { size: 32 }),
    paymasterAndData: packPaymasterAndData({
      paymaster: PAYMASTER,
      verificationGasLimit: DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
      postOpGasLimit: DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
      validUntil: 0,
      validAfter: 0,
      nextVerifier: makeKey(2n),
    }),
    signature: "0x",
  };
}

describe("PAYMASTER_APPROVE_TAG", () => {
  it("matches keccak256('quip.digest.paymasterApprove')", () => {
    const expected = keccak256(toHex("quip.digest.paymasterApprove"));
    expect(PAYMASTER_APPROVE_TAG).toBe(expected);
  });
});

describe("PAYMASTER_SIG_OFFSET", () => {
  it("equals 128 (matches the Solidity constant)", () => {
    expect(PAYMASTER_SIG_OFFSET).toBe(128);
  });
});

describe("userOpBindingHash", () => {
  it("matches the manual hash of the 8-tuple field set", () => {
    const userOp = baselineUserOp();
    const expected = keccak256(
      concat([
        pad(userOp.sender, { size: 32, dir: "left" }),
        pad(toHex(userOp.nonce), { size: 32 }),
        keccak256(userOp.initCode),
        keccak256(userOp.callData),
        userOp.accountGasLimits,
        pad(toHex(userOp.preVerificationGas), { size: 32 }),
        userOp.gasFees,
        keccak256(slice(userOp.paymasterAndData, 0, PAYMASTER_SIG_OFFSET)),
      ])
    );
    expect(userOpBindingHash(userOp)).toBe(expected);
  });

  it("changes when sender changes", () => {
    const base = userOpBindingHash(baselineUserOp());
    const mutated: PackedUserOperation = {
      ...baselineUserOp(),
      sender: "0x9999999999999999999999999999999999999999",
    };
    expect(userOpBindingHash(mutated)).not.toBe(base);
  });

  it("changes when nonce changes", () => {
    const base = userOpBindingHash(baselineUserOp());
    expect(userOpBindingHash({ ...baselineUserOp(), nonce: 8n })).not.toBe(base);
  });

  it("changes when initCode changes", () => {
    const base = userOpBindingHash(baselineUserOp());
    expect(
      userOpBindingHash({ ...baselineUserOp(), initCode: "0x99" })
    ).not.toBe(base);
  });

  it("changes when callData changes", () => {
    const base = userOpBindingHash(baselineUserOp());
    expect(
      userOpBindingHash({ ...baselineUserOp(), callData: "0x99" })
    ).not.toBe(base);
  });

  it("changes when accountGasLimits changes", () => {
    const base = userOpBindingHash(baselineUserOp());
    const mutated: PackedUserOperation = {
      ...baselineUserOp(),
      accountGasLimits: pad(toHex(0x9999n), { size: 32 }),
    };
    expect(userOpBindingHash(mutated)).not.toBe(base);
  });

  it("changes when preVerificationGas changes", () => {
    const base = userOpBindingHash(baselineUserOp());
    expect(
      userOpBindingHash({ ...baselineUserOp(), preVerificationGas: 99_999n })
    ).not.toBe(base);
  });

  it("changes when gasFees changes", () => {
    const base = userOpBindingHash(baselineUserOp());
    const mutated: PackedUserOperation = {
      ...baselineUserOp(),
      gasFees: pad(toHex(0x9999n), { size: 32 }),
    };
    expect(userOpBindingHash(mutated)).not.toBe(base);
  });

  it("changes when nextVerifier in paymasterAndData[:128] changes", () => {
    const base = userOpBindingHash(baselineUserOp());
    const mutated: PackedUserOperation = {
      ...baselineUserOp(),
      paymasterAndData: packPaymasterAndData({
        paymaster: PAYMASTER,
        verificationGasLimit: DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
        postOpGasLimit: DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
        validUntil: 0,
        validAfter: 0,
        nextVerifier: makeKey(0x99n),
      }),
    };
    expect(userOpBindingHash(mutated)).not.toBe(base);
  });

  it("changes when validUntil / validAfter in paymasterAndData[:128] changes", () => {
    const base = userOpBindingHash(baselineUserOp());
    const mutatedUntil: PackedUserOperation = {
      ...baselineUserOp(),
      paymasterAndData: packPaymasterAndData({
        paymaster: PAYMASTER,
        verificationGasLimit: DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
        postOpGasLimit: DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
        validUntil: 100,
        validAfter: 0,
        nextVerifier: makeKey(2n),
      }),
    };
    expect(userOpBindingHash(mutatedUntil)).not.toBe(base);

    const mutatedAfter: PackedUserOperation = {
      ...baselineUserOp(),
      paymasterAndData: packPaymasterAndData({
        paymaster: PAYMASTER,
        verificationGasLimit: DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
        postOpGasLimit: DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
        validUntil: 0,
        validAfter: 50,
        nextVerifier: makeKey(2n),
      }),
    };
    expect(userOpBindingHash(mutatedAfter)).not.toBe(base);
  });

  it("changes when paymaster gas limits in paymasterAndData[:128] change", () => {
    const base = userOpBindingHash(baselineUserOp());
    const mutated: PackedUserOperation = {
      ...baselineUserOp(),
      paymasterAndData: packPaymasterAndData({
        paymaster: PAYMASTER,
        verificationGasLimit:
          DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT + 1n,
        postOpGasLimit: DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
        validUntil: 0,
        validAfter: 0,
        nextVerifier: makeKey(2n),
      }),
    };
    expect(userOpBindingHash(mutated)).not.toBe(base);
  });

  it("does NOT change when the WOTS+ sig region of paymasterAndData mutates", () => {
    // The sig region is intentionally excluded from the binding hash so the
    // digest can be computed before the signature exists.
    const baseUserOp = baselineUserOp();
    const base = userOpBindingHash(baseUserOp);

    const withSig: PackedUserOperation = {
      ...baseUserOp,
      paymasterAndData: packPaymasterAndData({
        paymaster: PAYMASTER,
        verificationGasLimit: DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
        postOpGasLimit: DEFAULT_PAYMASTER_POST_OP_GAS_LIMIT,
        validUntil: 0,
        validAfter: 0,
        nextVerifier: makeKey(2n),
        sig: makeSig(0x99n),
      }),
    };
    expect(userOpBindingHash(withSig)).toBe(base);
  });

  it("throws when paymasterAndData is shorter than PAYMASTER_SIG_OFFSET", () => {
    const truncated: PackedUserOperation = {
      ...baselineUserOp(),
      paymasterAndData: "0xdeadbeef",
    };
    expect(() => userOpBindingHash(truncated)).toThrow();
  });
});

describe("paymasterUserOpDigest", () => {
  it("matches the manual hash (PAYMASTER_APPROVE_TAG | chainId | paymaster | currentVerifier | bindingHash)", () => {
    const chainId = 1n;
    const currentVerifier = makeKey(1n);
    const userOp = baselineUserOp();
    const bindingHash = userOpBindingHash(userOp);

    const expected = keccak256(
      concat([
        PAYMASTER_APPROVE_TAG,
        pad(toHex(chainId), { size: 32 }),
        pad(PAYMASTER, { size: 32, dir: "left" }),
        currentVerifier.publicSeed,
        currentVerifier.publicKeyHash,
        bindingHash,
      ])
    );
    expect(
      paymasterUserOpDigest(
        PAYMASTER,
        chainId,
        currentVerifier.publicSeed,
        currentVerifier.publicKeyHash,
        bindingHash
      )
    ).toBe(expected);
  });

  it("changes when chainId / paymaster / currentVerifier / bindingHash change", () => {
    const currentVerifier = makeKey(1n);
    const userOp = baselineUserOp();
    const bindingHash = userOpBindingHash(userOp);

    const base = paymasterUserOpDigest(
      PAYMASTER,
      1n,
      currentVerifier.publicSeed,
      currentVerifier.publicKeyHash,
      bindingHash
    );

    // Different chainId.
    expect(
      paymasterUserOpDigest(
        PAYMASTER,
        8453n,
        currentVerifier.publicSeed,
        currentVerifier.publicKeyHash,
        bindingHash
      )
    ).not.toBe(base);

    // Different paymaster.
    expect(
      paymasterUserOpDigest(
        "0x0000000000000000000000000000000000000099",
        1n,
        currentVerifier.publicSeed,
        currentVerifier.publicKeyHash,
        bindingHash
      )
    ).not.toBe(base);

    // Different currentVerifier seed.
    const alt = makeKey(99n);
    expect(
      paymasterUserOpDigest(
        PAYMASTER,
        1n,
        alt.publicSeed,
        currentVerifier.publicKeyHash,
        bindingHash
      )
    ).not.toBe(base);

    // Different currentVerifier publicKeyHash.
    expect(
      paymasterUserOpDigest(
        PAYMASTER,
        1n,
        currentVerifier.publicSeed,
        alt.publicKeyHash,
        bindingHash
      )
    ).not.toBe(base);

    // Different bindingHash.
    const otherBinding = userOpBindingHash({
      ...userOp,
      nonce: userOp.nonce + 1n,
    });
    expect(
      paymasterUserOpDigest(
        PAYMASTER,
        1n,
        currentVerifier.publicSeed,
        currentVerifier.publicKeyHash,
        otherBinding
      )
    ).not.toBe(base);
  });

  it("transitively reacts to every envelope field mutation via bindingHash", () => {
    // End-to-end check that mutating any envelope field changes the digest
    // (the binding hash is the channel through which they're bound).
    const cv = makeKey(1n);
    const chainId = 1n;
    const baseDigest = paymasterUserOpDigest(
      PAYMASTER,
      chainId,
      cv.publicSeed,
      cv.publicKeyHash,
      userOpBindingHash(baselineUserOp())
    );

    const mutations: ((u: PackedUserOperation) => PackedUserOperation)[] = [
      (u) => ({ ...u, sender: "0x9999999999999999999999999999999999999999" }),
      (u) => ({ ...u, nonce: u.nonce + 1n }),
      (u) => ({ ...u, initCode: "0x99" }),
      (u) => ({ ...u, callData: "0x99" }),
      (u) => ({ ...u, accountGasLimits: pad(toHex(0x9999n), { size: 32 }) as Hex }),
      (u) => ({ ...u, preVerificationGas: u.preVerificationGas + 1n }),
      (u) => ({ ...u, gasFees: pad(toHex(0x9999n), { size: 32 }) as Hex }),
    ];
    for (const m of mutations) {
      const mutated = m(baselineUserOp());
      const mutatedDigest = paymasterUserOpDigest(
        PAYMASTER,
        chainId,
        cv.publicSeed,
        cv.publicKeyHash,
        userOpBindingHash(mutated)
      );
      expect(mutatedDigest).not.toBe(baseDigest);
    }
  });
});

describe("packPaymasterAndData", () => {
  it("produces 2272 bytes total", () => {
    const out = packPaymasterAndData({
      paymaster: PAYMASTER,
      verificationGasLimit: DEFAULT_PAYMASTER_VERIFICATION_GAS_LIMIT,
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
      verificationGasLimit: validationGas,
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
    // [20:36) verificationGasLimit (uint128 big-endian)
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
      verificationGasLimit: 1n,
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
      verificationGasLimit: 1n,
      postOpGasLimit: 1n,
      validUntil: 0,
      validAfter: 0,
      nextVerifier: makeKey(1n),
    };
    expect(() =>
      packPaymasterAndData({ ...base, verificationGasLimit: 1n << 128n })
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
      verificationGasLimit: 1_234_567n,
      postOpGasLimit: 50_000n,
      validUntil: 9_999,
      validAfter: 42,
      nextVerifier: makeKey(0xabn),
      sig: makeSig(0xbeefn),
    };
    const packed = packPaymasterAndData(input);
    const out = decodePaymasterAndData(packed);
    expect(out.paymaster.toLowerCase()).toBe(PAYMASTER.toLowerCase());
    expect(out.verificationGasLimit).toBe(input.verificationGasLimit);
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
